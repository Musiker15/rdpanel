package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/bropines/rdpanel/internal/auth"
	"github.com/bropines/rdpanel/internal/crypto"
	"github.com/bropines/rdpanel/internal/db/dbtest"
	"github.com/bropines/rdpanel/internal/oidc"
	"github.com/bropines/rdpanel/internal/oidc/oidctest"
	"github.com/bropines/rdpanel/internal/store"
)

const (
	publicURL = "https://desk.example.test"
	adminURL  = "https://admin.example.test"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

type env struct {
	t        *testing.T
	st       *store.Store
	clk      *clock
	svc      *oidc.Service
	idp      *oidctest.IdP
	gh       *oidctest.IdP
	prov     *store.IdentityProvider
	ghProv   *store.IdentityProvider
	h        http.Handler
	jwt      *auth.ClientJWT
	webUsers []*store.User
	factor   *fakeFactor
}

func newEnv(t *testing.T, mutate func(p *store.IdentityProvider)) *env {
	t.Helper()
	d := dbtest.Open(t)
	clk := &clock{t: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}
	st := store.New(d).WithClock(clk.now)
	key, _ := crypto.RandomBytes(32)
	aead, _ := crypto.NewAEAD(key)
	jwtSvc, _ := auth.NewClientJWT([]byte("jwt-key"), clk.now)

	e := &env{t: t, st: st, clk: clk, jwt: jwtSvc, factor: &fakeFactor{totp: map[int64]string{}, email: map[int64]bool{}}}
	e.idp = oidctest.New(t, "panel-client", "s3cr3t")
	e.idp.Now = clk.now
	e.gh = oidctest.NewGitHub(t, "gh-client", "gh-secret")

	e.prov = &store.IdentityProvider{Slug: "authentik", Kind: store.ProviderOIDC, DisplayName: "Authentik",
		ClientID: "panel-client", Issuer: e.idp.Issuer(), PKCEEnabled: true, PKCEMethod: "S256", Enabled: true}
	if mutate != nil {
		mutate(e.prov)
	}
	e.addProvider(aead, e.prov, "s3cr3t")
	e.ghProv = &store.IdentityProvider{Slug: "github", Kind: store.ProviderGitHub, ClientID: "gh-client",
		PKCEEnabled: true, PKCEMethod: "S256", Enabled: true, AutoRegister: true, SortOrder: 1}
	e.addProvider(aead, e.ghProv, "gh-secret")

	e.svc = oidc.NewService(oidc.Options{Store: st, AEAD: aead, JWT: jwtSvc, PublicURL: publicURL, AdminURL: adminURL,
		TokenLifetime: time.Hour, JWTLifetime: time.Hour,
		GitHub: &oidc.GitHubEndpoints{AuthURL: e.gh.Server.URL + "/login/oauth/authorize",
			TokenURL: e.gh.Server.URL + "/login/oauth/access_token", APIURL: e.gh.Server.URL},
		WebLogin: func(w http.ResponseWriter, r *http.Request, u *store.User, next string) {
			e.webUsers = append(e.webUsers, u)
			http.Redirect(w, r, next, http.StatusFound)
		},
		SecondFactor: e.factor,
		EmailFactor: func(_ context.Context, u *store.User) (bool, error) {
			return e.factor.email[u.ID], nil
		},
		Limiter: auth.NewBackoff(auth.DefaultBackoffConfig, clk.now),
	})
	r := chi.NewRouter()
	r.Route("/api", func(api chi.Router) { oidc.Register(api, oidc.RouteDeps{Service: e.svc}) })
	e.h = r
	return e
}

func (e *env) addProvider(aead *crypto.AEAD, p *store.IdentityProvider, secret string) {
	ctx := context.Background()
	if err := e.st.IdentityProviders.Create(ctx, p); err != nil {
		e.t.Fatal(err)
	}
	enc, err := aead.SealString(secret, crypto.IdentityProviderClientSecretAD(p.ID))
	if err != nil {
		e.t.Fatal(err)
	}
	p.ClientSecretEnc = enc
	if err := e.st.IdentityProviders.Update(ctx, p); err != nil {
		e.t.Fatal(err)
	}
}

func (e *env) do(method, target, body string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

func (e *env) user(name, email string) *store.User {
	u := &store.User{Username: name, Email: email}
	if err := e.st.Users.Create(context.Background(), u); err != nil {
		e.t.Fatal(err)
	}
	return u
}

// startClient runs POST /api/oidc/auth and returns code and url.
func (e *env) startClient(op string) (string, string) {
	e.t.Helper()
	rec := e.do("POST", "/api/oidc/auth", `{"op":"`+op+`","id":"123456789","uuid":"dXVpZA==",
		"deviceInfo":{"os":"windows","type":"client","name":"HOST"},"apiDomain":"https://evil.example"}`)
	var resp map[string]string
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &resp) != nil || resp["code"] == "" {
		e.t.Fatalf("oidc/auth: %d %s", rec.Code, rec.Body.String())
	}
	u, err := url.Parse(resp["url"])
	if err != nil || !u.IsAbs() {
		e.t.Fatalf("url not absolute: %q", resp["url"])
	}
	if got := u.Query().Get("redirect_uri"); got != publicURL+"/api/oidc/callback" {
		e.t.Fatalf("redirect_uri %q (apiDomain must be ignored)", got)
	}
	return resp["code"], resp["url"]
}

func (e *env) callback(q url.Values, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	return e.do("GET", "/api/oidc/callback?"+q.Encode(), "", cookies...)
}

func (e *env) poll(code, id, uuid string) string {
	e.t.Helper()
	q := url.Values{"code": {code}, "id": {id}, "uuid": {uuid}}
	rec := e.do("GET", "/api/oidc/auth-query?"+q.Encode(), "")
	if rec.Code != 200 {
		e.t.Fatalf("auth-query status %d", rec.Code)
	}
	return strings.TrimSpace(rec.Body.String())
}

// clientLogin runs the whole client flow up to the callback.
func (e *env) clientLogin(op string, id oidctest.Identity) (code string, cb *httptest.ResponseRecorder) {
	e.t.Helper()
	code, authURL := e.startClient(op)
	idp := e.idp
	if op == "github" {
		idp = e.gh
	}
	q, err := idp.Authorize(authURL, id)
	if err != nil {
		e.t.Fatal(err)
	}
	return code, e.confirmIfAsked(e.callback(q))
}

var confirmTokenRe = regexp.MustCompile(`name="token" value="([^"]+)"`)

// confirm posts the confirmation form of page with action and code.
func (e *env) confirm(page *httptest.ResponseRecorder, action, code string) *httptest.ResponseRecorder {
	e.t.Helper()
	m := confirmTokenRe.FindStringSubmatch(page.Body.String())
	if m == nil {
		e.t.Fatalf("no confirmation form: %d %s", page.Code, page.Body.String())
	}
	form := url.Values{"token": {html.UnescapeString(m[1])}, "action": {action}, "code": {code}}
	req := httptest.NewRequest("POST", "/api/oidc/confirm", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	e.h.ServeHTTP(rec, req)
	return rec
}

// confirmIfAsked approves the sign-in when cb is the confirmation page.
func (e *env) confirmIfAsked(cb *httptest.ResponseRecorder) *httptest.ResponseRecorder {
	e.t.Helper()
	if cb.Code != 200 || !confirmTokenRe.MatchString(cb.Body.String()) {
		return cb
	}
	return e.confirm(cb, "approve", "")
}

const pendingBody = `{"error":"No authed oidc is found"}`
const invalidBody = `{"error":"Invalid or expired code"}`

func TestLoginOptions(t *testing.T) {
	e := newEnv(t, nil)
	rec := e.do("GET", "/api/login-options", "")
	want := `["common-oidc/[{\"name\":\"authentik\"},{\"name\":\"github\"}]","oidc/authentik","oidc/github"]`
	if rec.Code != 200 || strings.TrimSpace(rec.Body.String()) != want {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	e.prov.Enabled = false
	_ = e.st.IdentityProviders.Update(context.Background(), e.prov)
	e.ghProv.Enabled = false
	_ = e.st.IdentityProviders.Update(context.Background(), e.ghProv)
	rec = e.do("GET", "/api/login-options", "")
	if strings.TrimSpace(rec.Body.String()) != `[]` {
		t.Fatalf("empty: %s", rec.Body.String())
	}
}

func TestClientFlowEndToEnd(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	alice := e.user("alice", "alice@example.test")
	if err := e.st.UserIdentities.Create(ctx, &store.UserIdentity{UserID: alice.ID, ProviderID: e.prov.ID, Subject: "sub-alice"}); err != nil {
		t.Fatal(err)
	}

	code, authURL := e.startClient("authentik")
	if got := e.poll(code, "123456789", "dXVpZA=="); got != pendingBody {
		t.Fatalf("pending: %s", got)
	}
	u, _ := url.Parse(authURL)
	if u.Query().Get("code_challenge_method") != "S256" || u.Query().Get("code_challenge") == "" || u.Query().Get("nonce") == "" {
		t.Fatalf("pkce/nonce missing: %s", authURL)
	}
	q, err := e.idp.Authorize(authURL, oidctest.Identity{Subject: "sub-alice", Name: "Alice A."})
	if err != nil {
		t.Fatal(err)
	}
	cb := e.callback(q)
	if cb.Code != 200 || !strings.Contains(cb.Body.String(), "Sign in to RustDesk?") || !strings.Contains(cb.Body.String(), "123456789") {
		t.Fatalf("confirmation page: %d %s", cb.Code, cb.Body.String())
	}
	// Nothing for the client until the sign-in is confirmed in this browser.
	if got := e.poll(code, "123456789", "dXVpZA=="); got != pendingBody {
		t.Fatalf("before confirmation: %s", got)
	}
	page := cb
	cb = e.confirm(page, "approve", "")
	if cb.Code != 200 || !strings.Contains(cb.Body.String(), "Signed in") {
		t.Fatalf("confirm: %d %s", cb.Code, cb.Body.String())
	}
	// The form is single-use.
	if rec := e.confirm(page, "approve", ""); rec.Code != 400 {
		t.Fatalf("confirm replay: %d", rec.Code)
	}
	// Replayed callback (same state) is refused.
	if rec := e.callback(q); rec.Code != 400 {
		t.Fatalf("replay: %d", rec.Code)
	}
	// Wrong device: refused without consuming the code.
	if got := e.poll(code, "123456789", "b3RoZXI="); got != invalidBody {
		t.Fatalf("foreign uuid: %s", got)
	}
	if got := e.poll(code, "999", "dXVpZA=="); got != invalidBody {
		t.Fatalf("foreign id: %s", got)
	}
	got := e.poll(code, "123456789", "dXVpZA==")
	var body struct {
		AccessToken string         `json:"access_token"`
		Type        string         `json:"type"`
		User        map[string]any `json:"user"`
	}
	if err := json.Unmarshal([]byte(got), &body); err != nil || body.Type != "access_token" || body.AccessToken == "" {
		t.Fatalf("success: %s", got)
	}
	if body.User["name"] != "alice" || body.User["status"] != float64(1) || body.User["is_admin"] != false {
		t.Fatalf("user: %v", body.User)
	}
	info, ok := body.User["info"].(map[string]any)
	if !ok || info["email_verification"] != false || info["email_alarm_notification"] != false {
		t.Fatalf("info must be an object: %v", body.User["info"])
	}
	claims, err := e.jwt.Verify(body.AccessToken)
	if err != nil || int64(claims.UserID) != alice.ID {
		t.Fatalf("jwt: %v %+v", err, claims)
	}
	tok, err := e.st.AuthTokens.GetActive(ctx, store.TokenClient, crypto.HashToken(body.AccessToken))
	if err != nil || tok.DeviceRustdeskID != "123456789" || tok.DeviceUUID != "dXVpZA==" || tok.ClientPlatform != "windows" {
		t.Fatalf("token row: %v %+v", err, tok)
	}
	// The code is single use.
	if got := e.poll(code, "123456789", "dXVpZA=="); got != invalidBody {
		t.Fatalf("second poll: %s", got)
	}
	var n int
	_ = e.st.Querier().QueryRowContext(ctx, `SELECT count(*) FROM login_events WHERE method='oidc' AND result='success' AND user_id=?`, alice.ID).Scan(&n)
	if n != 1 {
		t.Fatalf("login events = %d", n)
	}
}

func TestClientFlowUnknownProviderAndValidation(t *testing.T) {
	e := newEnv(t, nil)
	rec := e.do("POST", "/api/oidc/auth", `{"op":"nope","id":"1","uuid":"u"}`)
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("%s", rec.Body.String())
	}
	rec = e.do("POST", "/api/oidc/auth", `{"op":"authentik"}`)
	if !strings.Contains(rec.Body.String(), `"error"`) {
		t.Fatalf("missing device: %s", rec.Body.String())
	}
	if got := e.poll("garbage", "1", "u"); got != invalidBody {
		t.Fatalf("garbage code: %s", got)
	}
}

func TestStateExpires(t *testing.T) {
	e := newEnv(t, nil)
	e.user("alice", "")
	code, authURL := e.startClient("authentik")
	e.clk.advance(6 * time.Minute)
	if got := e.poll(code, "123456789", "dXVpZA=="); got != invalidBody {
		t.Fatalf("expired poll: %s", got)
	}
	q, _ := e.idp.Authorize(authURL, oidctest.Identity{Subject: "x"})
	if rec := e.callback(q); rec.Code != 400 {
		t.Fatalf("expired callback: %d", rec.Code)
	}
}

func pollResult(t *testing.T, e *env, code string) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(e.poll(code, "123456789", "dXVpZA==")), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestLinkingRules(t *testing.T) {
	type tc struct {
		name       string
		linkEmail  bool
		autoReg    bool
		verified   bool
		panelOK    bool   // the existing user's address is verified in the panel
		wantUser   string // "existing", "new", "" (error)
		wantErrSub string
	}
	cases := []tc{
		{"verified email links when enabled", true, false, true, true, "existing", ""},
		{"unverified email never links", true, false, false, true, "", "No account is linked"},
		{"unverified email + auto-register creates a new user", true, true, false, true, "new", ""},
		{"verified email but linking disabled", false, false, true, true, "", "No account is linked"},
		{"linking disabled + auto-register creates new user", false, true, true, true, "new", ""},
		// The panel must have verified the address too.
		{"address not verified in the panel never links", true, true, true, false, "", "not verified in the panel"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t, func(p *store.IdentityProvider) {
				p.LinkByVerifiedEmail, p.AutoRegister = c.linkEmail, c.autoReg
			})
			existing := e.user("bob", "Bob@Example.test")
			if c.panelOK {
				at := e.clk.now()
				if err := e.st.Users.SetEmailVerified(context.Background(), existing.ID, existing.Email, &at); err != nil {
					t.Fatal(err)
				}
			}
			code, cb := e.clientLogin("authentik", oidctest.Identity{Subject: "sub-bob", Email: "bob@example.test",
				EmailVerified: c.verified, PreferredUsername: "bob", Name: "Bob"})
			if cb.Code != 200 {
				t.Fatalf("callback %d", cb.Code)
			}
			m := pollResult(t, e, code)
			ctx := context.Background()
			ident, identErr := e.st.UserIdentities.GetByProviderSubject(ctx, e.prov.ID, "sub-bob")
			switch c.wantUser {
			case "":
				if s, _ := m["error"].(string); !strings.Contains(s, c.wantErrSub) {
					t.Fatalf("want error %q, got %v", c.wantErrSub, m)
				}
				if identErr == nil {
					t.Fatal("identity must not be linked")
				}
			case "existing":
				if m["access_token"] == nil || identErr != nil || ident.UserID != existing.ID {
					t.Fatalf("want link to existing: %v %v", m, identErr)
				}
			case "new":
				if m["access_token"] == nil || identErr != nil || ident.UserID == existing.ID {
					t.Fatalf("want new user: %v %v", m, identErr)
				}
				nu, _ := e.st.Users.GetByID(ctx, ident.UserID)
				if nu.Username == "bob" || nu.HasPassword() {
					t.Fatalf("new user %+v", nu)
				}
				if !c.verified && nu.Email != "" {
					t.Fatal("unverified email must not be copied to users.email")
				}
			}
		})
	}
}

func TestDisabledUserCannotLogin(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	u := e.user("carol", "")
	_ = e.st.UserIdentities.Create(ctx, &store.UserIdentity{UserID: u.ID, ProviderID: e.prov.ID, Subject: "c"})
	u.Status = store.UserDisabled
	_ = e.st.Users.Update(ctx, u)
	code, _ := e.clientLogin("authentik", oidctest.Identity{Subject: "c"})
	if m := pollResult(t, e, code); m["error"] != "This account is disabled." {
		t.Fatalf("%v", m)
	}
}

func TestBadIDTokens(t *testing.T) {
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, setup := range map[string]func(e *env){
		"wrong signing key": func(e *env) { e.idp.SignWith = other },
		"nonce mismatch":    func(e *env) { e.idp.NonceOverride = "attacker-nonce" },
	} {
		t.Run(name, func(t *testing.T) {
			e := newEnv(t, nil)
			ctx := context.Background()
			u := e.user("dave", "")
			_ = e.st.UserIdentities.Create(ctx, &store.UserIdentity{UserID: u.ID, ProviderID: e.prov.ID, Subject: "d"})
			setup(e)
			code, cb := e.clientLogin("authentik", oidctest.Identity{Subject: "d"})
			if !strings.Contains(cb.Body.String(), "Sign-in failed") {
				t.Fatalf("callback: %s", cb.Body.String())
			}
			if m := pollResult(t, e, code); m["access_token"] != nil || m["error"] == nil {
				t.Fatalf("%v", m)
			}
		})
	}
}

func TestIdPDenied(t *testing.T) {
	e := newEnv(t, nil)
	code, authURL := e.startClient("authentik")
	u, _ := url.Parse(authURL)
	rec := e.callback(url.Values{"state": {u.Query().Get("state")}, "error": {"access_denied"}})
	if rec.Code != 200 || !strings.Contains(rec.Body.String(), "cancelled or denied") {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if m := pollResult(t, e, code); !strings.Contains(m["error"].(string), "denied") {
		t.Fatalf("%v", m)
	}
}

func TestGitHubFlow(t *testing.T) {
	e := newEnv(t, nil)
	code, cb := e.clientLogin("github", oidctest.Identity{GitHubID: 4242, GitHubLogin: "Octo Cat",
		Email: "octo@example.test", EmailVerified: true, Name: "Octo"})
	if cb.Code != 200 || !strings.Contains(cb.Body.String(), "Signed in") {
		t.Fatalf("callback: %d %s", cb.Code, cb.Body.String())
	}
	m := pollResult(t, e, code)
	if m["access_token"] == nil {
		t.Fatalf("%v", m)
	}
	ctx := context.Background()
	ident, err := e.st.UserIdentities.GetByProviderSubject(ctx, e.ghProv.ID, "4242")
	if err != nil || !ident.EmailVerified || ident.Email != "octo@example.test" {
		t.Fatalf("%v %+v", err, ident)
	}
	u, _ := e.st.Users.GetByID(ctx, ident.UserID)
	if u.Username != "octocat" || u.Email != "octo@example.test" {
		t.Fatalf("user %+v", u)
	}
}

// handoffTicket checks that a panel callback redirected to the admin host's
// completion endpoint and returns the ticket.
func handoffTicket(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	loc := rec.Header().Get("Location")
	u, err := url.Parse(loc)
	if rec.Code != http.StatusFound || err != nil || adminURL+oidc.HandoffPath != u.Scheme+"://"+u.Host+u.Path {
		t.Fatalf("callback must hand off to the admin host: %d %s", rec.Code, loc)
	}
	return u.Query().Get("ticket")
}

// complete calls the admin-host completion endpoint.
func (e *env) complete(ticket string, cookies ...*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, oidc.HandoffPath+"?ticket="+url.QueryEscape(ticket), nil)
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	e.svc.CompleteWeb(rec, req)
	return rec
}

func TestWebFlowBrowserBinding(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	u := e.user("erin", "")
	_ = e.st.UserIdentities.Create(ctx, &store.UserIdentity{UserID: u.ID, ProviderID: e.prov.ID, Subject: "erin"})

	start := func(next string) (string, *http.Cookie) {
		rec := httptest.NewRecorder()
		authURL, err := e.svc.BeginWebLogin(ctx, rec, "authentik", next)
		if err != nil {
			t.Fatal(err)
		}
		var c *http.Cookie
		for _, ck := range rec.Result().Cookies() {
			if ck.Name == oidc.BindingCookie {
				c = ck
			}
		}
		if c == nil || !c.HttpOnly {
			t.Fatal("binding cookie missing")
		}
		return authURL, c
	}
	// The public-host callback never needs the cookie and never logs in.
	callback := func(next string) (string, *http.Cookie) {
		authURL, c := start(next)
		q, _ := e.idp.Authorize(authURL, oidctest.Identity{Subject: "erin"})
		return handoffTicket(t, e.callback(q)), c
	}
	loc := func(rec *httptest.ResponseRecorder) string { return rec.Header().Get("Location") }

	// Missing cookie (login CSRF): refused, and the ticket is burnt.
	ticket, c := callback("/devices?x=1")
	if rec := e.complete(ticket); loc(rec) != "/login?error=oidc_session_mismatch" {
		t.Fatalf("no cookie: %d %s", rec.Code, loc(rec))
	}
	if rec := e.complete(ticket, c); loc(rec) != "/login?error=oidc_expired" || len(e.webUsers) != 0 {
		t.Fatalf("ticket reuse after mismatch: %s", loc(rec))
	}
	// Wrong cookie (another browser's flow).
	ticket, _ = callback("/")
	_, other := start("/")
	if rec := e.complete(ticket, other); loc(rec) != "/login?error=oidc_session_mismatch" {
		t.Fatalf("wrong cookie: %s", loc(rec))
	}
	// Expired ticket.
	ticket, c = callback("/")
	e.clk.advance(oidc.HandoffTTL + time.Second)
	if rec := e.complete(ticket, c); loc(rec) != "/login?error=oidc_expired" {
		t.Fatalf("expired: %s", loc(rec))
	}
	// Unknown ticket.
	if rec := e.complete("nope", c); loc(rec) != "/login?error=oidc_expired" {
		t.Fatalf("unknown: %s", loc(rec))
	}
	if len(e.webUsers) != 0 {
		t.Fatalf("no login expected: %v", e.webUsers)
	}
	// Success: WebLogin is called with the safe redirect path; replay fails.
	ticket, c = callback("/devices?x=1")
	rec := e.complete(ticket, c)
	if rec.Code != http.StatusFound || loc(rec) != "/devices?x=1" || len(e.webUsers) != 1 || e.webUsers[0].ID != u.ID {
		t.Fatalf("with cookie: %d %s %v", rec.Code, loc(rec), e.webUsers)
	}
	if rec := e.complete(ticket, c); loc(rec) != "/login?error=oidc_expired" || len(e.webUsers) != 1 {
		t.Fatalf("replay: %s", loc(rec))
	}
	// Open redirect attempt falls back to "/".
	ticket, c = callback("//evil.example/x")
	if rec := e.complete(ticket, c); loc(rec) != "/" {
		t.Fatalf("open redirect: %s", loc(rec))
	}
	// IdP errors go straight back to the admin host's login page.
	authURL, _ := start("/")
	u2, _ := url.Parse(authURL)
	rec = e.callback(url.Values{"state": {u2.Query().Get("state")}, "error": {"access_denied"}})
	if loc(rec) != adminURL+"/login?error=oidc_denied" {
		t.Fatalf("denied: %s", loc(rec))
	}
}

func TestBindFlow(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	frank := e.user("frank", "")
	other := e.user("other", "")
	_ = e.st.UserIdentities.Create(ctx, &store.UserIdentity{UserID: other.ID, ProviderID: e.prov.ID, Subject: "taken"})

	bind := func(sub string) string {
		rec := httptest.NewRecorder()
		authURL, err := e.svc.BeginBind(ctx, rec, "authentik", frank.ID, "")
		if err != nil {
			t.Fatal(err)
		}
		q, _ := e.idp.Authorize(authURL, oidctest.Identity{Subject: sub, Email: "f@example.test", EmailVerified: true})
		ticket := handoffTicket(t, e.callback(q))
		return e.complete(ticket, rec.Result().Cookies()[0]).Header().Get("Location")
	}
	if loc := bind("taken"); loc != "/my/profile?link_error=already_linked" {
		t.Fatalf("taken: %s", loc)
	}
	if loc := bind("frank-sub"); loc != "/my/profile?linked=authentik" {
		t.Fatalf("bind: %s", loc)
	}
	ident, err := e.st.UserIdentities.GetByProviderSubject(ctx, e.prov.ID, "frank-sub")
	if err != nil || ident.UserID != frank.ID {
		t.Fatalf("%v %+v", err, ident)
	}
	if loc := bind("frank-second"); loc != "/my/profile?link_error=already_linked" {
		t.Fatalf("second identity of same provider: %s", loc)
	}
}

func TestSafeRedirectPath(t *testing.T) {
	for in, want := range map[string]string{
		"/devices":             "/devices",
		"/a?b=c#d":             "/a?b=c#d",
		"":                     "/",
		"//evil.example":       "/",
		"/\\evil.example":      "/",
		"https://evil.example": "/",
		"javascript:alert(1)":  "/",
		"devices":              "/",
		"/a\nb":                "/",
	} {
		if got := oidc.SafeRedirectPath(in, "/"); got != want {
			t.Errorf("%q: got %q want %q", in, got, want)
		}
	}
}

func TestDiscoverIssuerMismatch(t *testing.T) {
	e := newEnv(t, nil)
	p := *e.prov
	p.Issuer = e.idp.Issuer() + "/other"
	if _, err := e.svc.Discover(context.Background(), &p); err == nil {
		t.Fatal("expected discovery failure")
	}
	m, err := e.svc.Discover(context.Background(), e.prov)
	if err != nil || m.TokenEndpoint != e.idp.Issuer()+"/token" {
		t.Fatalf("%v %+v", err, m)
	}
}

func TestNotConfiguredWithoutPublicURL(t *testing.T) {
	e := newEnv(t, nil)
	svc := oidc.NewService(oidc.Options{Store: e.st, JWT: e.jwt})
	if _, _, err := svc.BeginClient(context.Background(), "authentik", oidc.ClientDevice{ID: "1", UUID: "u"}); err != oidc.ErrNotConfigured {
		t.Fatalf("%v", err)
	}
}

// fakeFactor is the panel's TOTP and e-mail factor: totp holds the one valid
// code of each enrolled user.
type fakeFactor struct {
	totp  map[int64]string
	email map[int64]bool
}

func (f *fakeFactor) Enrolled(_ context.Context, userID int64) (bool, error) {
	_, ok := f.totp[userID]
	return ok, nil
}

func (f *fakeFactor) Verify(_ context.Context, userID int64, code string) (bool, error) {
	want, ok := f.totp[userID]
	return ok && code == want, nil
}

// A client sign-in through an IdP is confirmed on a page naming the device,
// asks for the TOTP code of an account that has one, and is refused for an
// account that signs in with e-mailed codes.
func TestClientFlowConfirmation(t *testing.T) {
	e := newEnv(t, nil)
	ctx := context.Background()
	link := func(name string) *store.User {
		u := e.user(name, name+"@example.test")
		if err := e.st.UserIdentities.Create(ctx, &store.UserIdentity{UserID: u.ID, ProviderID: e.prov.ID, Subject: "sub-" + name}); err != nil {
			t.Fatal(err)
		}
		return u
	}
	signIn := func(name string) (string, *httptest.ResponseRecorder) {
		t.Helper()
		code, authURL := e.startClient("authentik")
		q, err := e.idp.Authorize(authURL, oidctest.Identity{Subject: "sub-" + name})
		if err != nil {
			t.Fatal(err)
		}
		return code, e.callback(q)
	}

	// Cancel: the client gets an error, the form is spent.
	link("carol")
	code, page := signIn("carol")
	if rec := e.confirm(page, "cancel", ""); rec.Code != 200 || !strings.Contains(rec.Body.String(), "cancelled") {
		t.Fatalf("cancel: %d %s", rec.Code, rec.Body.String())
	}
	if m := pollResult(t, e, code); !strings.Contains(fmt.Sprint(m["error"]), "cancelled") {
		t.Fatalf("after cancel: %v", m)
	}
	if rec := e.confirm(page, "approve", ""); rec.Code != 400 {
		t.Fatalf("approve after cancel: %d", rec.Code)
	}

	// TOTP: the code is asked for, a wrong one keeps the flow pending.
	dave := link("dave")
	e.factor.totp[dave.ID] = "123456"
	code, page = signIn("dave")
	if !strings.Contains(page.Body.String(), `name="code"`) {
		t.Fatalf("no code field: %s", page.Body.String())
	}
	if rec := e.confirm(page, "approve", "000000"); rec.Code != 401 || !strings.Contains(rec.Body.String(), "Invalid verification code") {
		t.Fatalf("wrong code: %d %s", rec.Code, rec.Body.String())
	}
	if got := e.poll(code, "123456789", "dXVpZA=="); got != pendingBody {
		t.Fatalf("after a wrong code: %s", got)
	}
	if rec := e.confirm(page, "approve", "123456"); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Signed in") {
		t.Fatalf("right code: %d %s", rec.Code, rec.Body.String())
	}
	if m := pollResult(t, e, code); m["access_token"] == nil {
		t.Fatalf("token after TOTP: %v", m)
	}
	// Codes are bounded per user, shared with the panel and the client API.
	code, page = signIn("dave")
	last := 0
	for range auth.SecondFactorLimit + 1 {
		last = e.confirm(page, "approve", "000000").Code
	}
	if last != 429 {
		t.Fatalf("code attempts not bounded: last status %d", last)
	}
	_ = code

	// E-mail factor: refused, nothing to confirm.
	erin := link("erin")
	e.factor.email[erin.ID] = true
	code, page = signIn("erin")
	if page.Code != 403 || confirmTokenRe.MatchString(page.Body.String()) || !strings.Contains(page.Body.String(), "e-mail") {
		t.Fatalf("e-mail factor: %d %s", page.Code, page.Body.String())
	}
	if m := pollResult(t, e, code); m["access_token"] != nil {
		t.Fatalf("token for an e-mail factor account: %v", m)
	}

	// A forged or tampered token is refused.
	for _, tok := range []string{"", "bm90LWEtdG9rZW4", strings.Repeat("A", 600)} {
		form := url.Values{"token": {tok}, "action": {"approve"}}
		req := httptest.NewRequest("POST", "/api/oidc/confirm", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		e.h.ServeHTTP(rec, req)
		if rec.Code != 400 {
			t.Fatalf("token %q: %d", tok, rec.Code)
		}
	}
}
