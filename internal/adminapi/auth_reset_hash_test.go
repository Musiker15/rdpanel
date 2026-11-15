package adminapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

	"github.com/bropines/rdpanel/internal/auth"
)

// newTEnvWithHasher is newTEnv with the admin API served using h.
func newTEnvWithHasher(t *testing.T, h *auth.Hasher) *tenv {
	t.Helper()
	e := newTEnv(t)
	e.deps.Hasher = h
	r := chi.NewRouter()
	r.Route("/api/v1/admin", func(r chi.Router) { Register(r, e.deps) })
	e.srv.Close()
	e.srv = httptest.NewServer(r)
	t.Cleanup(e.srv.Close)
	return e
}

// The reset endpoint is public and mounted even without SMTP. A request with
// a made-up token must be refused before the new password is hashed, so
// anonymous callers cannot make the panel run argon2id for free. The hasher
// here panics if it is ever used (zero lanes), which turns a hash into a
// failed request.
func TestPasswordResetChecksTokenBeforeHashing(t *testing.T) {
	e := newTEnvWithHasher(t, &auth.Hasher{Params: auth.Argon2Params{Memory: 1024, Time: 1, Threads: 0, SaltLen: 16, KeyLen: 32}})
	c := e.client()
	code, m, _ := c.do(http.MethodPost, "/auth/password/reset",
		map[string]string{"token": "not-a-real-token", "new_password": "brand-new-password"})
	if code != http.StatusBadRequest || errCode(m) != "invalid_token" {
		t.Fatalf("reset with a made-up token: %d %v", code, m)
	}
}
