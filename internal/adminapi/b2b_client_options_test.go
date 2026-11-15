package adminapi

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/bropines/rdpanel/internal/clientopts"
	"github.com/bropines/rdpanel/internal/store"
)

func TestClientOptions(t *testing.T) {
	e := newB2Env(t, b2opts{})
	admin, _ := e.as("root", store.RoleAdmin)
	user, _ := e.as("bob", store.RoleUser)

	code, m, _ := user.do(http.MethodGet, "/server/client-options", nil)
	wantErr(t, "user get", code, 403, m, "forbidden")

	code, m, _ = admin.do(http.MethodGet, "/server/client-options", nil)
	want(t, "get unset", code, 200, m)
	if m["pushed"] != false || m["ice_servers"] != "" || m["webrtc_congestion_control"] != nil || m["modified_at"] != nil {
		t.Fatalf("unset: %v", m)
	}

	code, m, _ = admin.do(http.MethodPut, "/server/client-options", map[string]any{
		"ice_servers": "stun:stun.example.com:3478\nturn://u:turn-secret@turn.example.com:3478", "webrtc_congestion_control": true})
	want(t, "put", code, 200, m)
	if m["pushed"] != true || m["ice_servers"] != "stun:stun.example.com:3478\nturn://u:turn-secret@turn.example.com:3478" ||
		m["webrtc_congestion_control"] != true || m["modified_at"] == nil {
		t.Fatalf("put: %v", m)
	}

	// The heartbeat strategy (here a fresh service, as after a restart) sees it.
	strat, err := clientopts.New(e.st, e.aead, nil).StrategyFor(e.ctx, nil)
	if err != nil || strat == nil || strat.ConfigOptions[clientopts.OptionICEServers] !=
		"stun:stun.example.com:3478,turn://u:turn-secret@turn.example.com:3478" ||
		strat.ConfigOptions[clientopts.OptionWebRTCCongestion] != "Y" {
		t.Fatalf("strategy: %+v %v", strat, err)
	}

	for _, bad := range []map[string]any{
		{"ice_servers": "turn:no-credentials.example.com:3478"},
		{"ice_servers": "http://example.com"},
		{"ice_servers": "stun:a.example.com", "extra": 1},
		{"webrtc_congestion_control": "Y"},
	} {
		code, m, _ := admin.do(http.MethodPut, "/server/client-options", bad)
		wantErr(t, "invalid put", code, 400, m, "validation_failed")
	}

	// Clearing keeps pushing (empty values remove the options on clients).
	code, m, _ = admin.do(http.MethodPut, "/server/client-options", map[string]any{"ice_servers": "", "webrtc_congestion_control": nil})
	want(t, "clear", code, 200, m)
	if m["pushed"] != true || m["ice_servers"] != "" || m["webrtc_congestion_control"] != nil {
		t.Fatalf("clear: %v", m)
	}

	// Audited without the TURN credentials.
	rows, _, err := e.st.AdminAudit.ListPanel(e.ctx, store.AdminAuditQuery{ActionPrefix: "server.client_options"})
	if err != nil || len(rows) != 2 {
		t.Fatalf("audit rows %d %v", len(rows), err)
	}
	for _, r := range rows {
		b, _ := json.Marshal(r.Details)
		if strings.Contains(string(b), "turn-secret") || strings.Contains(string(b), "example.com") {
			t.Fatalf("audit leaked: %s", b)
		}
	}
}

func TestClientOptionsProbe(t *testing.T) {
	e := newB2Env(t, b2opts{})
	admin, _ := e.as("root", store.RoleAdmin)
	user, _ := e.as("bob", store.RoleUser)

	code, m, _ := user.do(http.MethodPost, "/server/client-options/probe", map[string]any{
		"ice_servers": "stun:127.0.0.1:3478",
	})
	wantErr(t, "user probe", code, 403, m, "forbidden")

	code, m, _ = admin.do(http.MethodPost, "/server/client-options/probe", map[string]any{
		"ice_servers": "stun:127.0.0.1:3478\nbad://url",
	})
	want(t, "admin probe", code, 200, m)
	items, ok := m["items"].([]any)
	if !ok || len(items) != 2 {
		t.Fatalf("expected 2 items, got %v", m)
	}
	// The 127.0.0.1 should be refused by default SSRF guard
	item0 := items[0].(map[string]any)
	if item0["reachable"] != false || !strings.Contains(item0["error"].(string), "SSRF guard") {
		t.Fatalf("expected SSRF error on 127.0.0.1, got %v", item0)
	}
}

func TestClientOptionsFetchSTUN(t *testing.T) {
	e := newB2Env(t, b2opts{})
	admin, _ := e.as("root", store.RoleAdmin)
	user, _ := e.as("bob", store.RoleUser)

	code, m, _ := user.do(http.MethodPost, "/server/client-options/fetch-stun", nil)
	wantErr(t, "user fetch-stun", code, 403, m, "forbidden")

	code, m, _ = admin.do(http.MethodPost, "/server/client-options/fetch-stun", map[string]any{
		"source_url": "ftp://bad-url",
	})
	wantErr(t, "invalid scheme", code, 400, m, "validation_failed")

	// Hermetic list source (no internet). Its candidates point at loopback and
	// private addresses: they are refused by the SSRF guard, never probed.
	src := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "# list\n127.0.0.1:3478\n10.0.0.1\n[::1]:3478\n")
	}))
	t.Cleanup(src.Close)
	code, m, _ = admin.do(http.MethodPost, "/server/client-options/fetch-stun", map[string]any{
		"source_url": src.URL, "limit": 3,
	})
	want(t, "admin fetch-stun", code, 200, m)
	if m["source"] != src.URL || m["fetched_count"] != float64(3) || m["working_count"] != float64(0) {
		t.Fatalf("fetch-stun: %v", m)
	}
	if items, ok := m["items"].([]any); !ok || len(items) != 0 {
		t.Fatalf("expected no working items, got %v", m)
	}
}

// RustDesk 1.5.3 ignores ice-servers from heartbeats: the options report how
// many devices that affects, and an opt-in hands the list to the install
// commands of /clients (signed-in users only, never by default).
func TestClientOptionsICEForInstall(t *testing.T) {
	e := newB2Env(t, b2opts{})
	admin, _ := e.as("root", store.RoleAdmin)
	user, _ := e.as("bob", store.RoleUser)
	for id, v := range map[string]string{"111": "1.4.9", "222": "1.5.3", "333": "1.6.0", "444": ""} {
		if err := e.st.Devices.Create(e.ctx, &store.Device{RustdeskID: id, ClientVersion: v}); err != nil {
			t.Fatal(err)
		}
	}
	ice := "stun:stun.example.com:3478\nturn://u:turn-secret@turn.example.com:3478"

	code, m, _ := admin.do(http.MethodPut, "/server/client-options", map[string]any{"ice_servers": ice})
	want(t, "put", code, 200, m)
	if m["ice_servers_in_install"] != false || b2bNum(m["devices_ignoring_ice"]) != 2 {
		t.Fatalf("default off, 2 devices on 1.5.3+: %v", m)
	}
	if _, m, _ := user.do(http.MethodGet, "/clients", nil); m["ice_servers"] != nil {
		t.Fatalf("ICE servers in /clients while off: %v", m["ice_servers"])
	}

	code, m, _ = admin.do(http.MethodPut, "/server/client-options", map[string]any{"ice_servers": ice, "ice_servers_in_install": true})
	want(t, "opt in", code, 200, m)
	if m["ice_servers_in_install"] != true {
		t.Fatalf("opt in: %v", m)
	}
	if _, m, _ := user.do(http.MethodGet, "/clients", nil); m["ice_servers"] != "stun:stun.example.com:3478,turn://u:turn-secret@turn.example.com:3478" {
		t.Fatalf("ICE servers in /clients: %v", m["ice_servers"])
	}

	// A PUT without the field keeps it; false turns it off again.
	code, m, _ = admin.do(http.MethodPut, "/server/client-options", map[string]any{"ice_servers": ice, "webrtc_congestion_control": true})
	want(t, "keep", code, 200, m)
	if m["ice_servers_in_install"] != true {
		t.Fatalf("omitted field reset the opt-in: %v", m)
	}
	code, m, _ = admin.do(http.MethodPut, "/server/client-options", map[string]any{"ice_servers": ice, "ice_servers_in_install": false})
	want(t, "opt out", code, 200, m)
	if _, m, _ := user.do(http.MethodGet, "/clients", nil); m["ice_servers"] != nil {
		t.Fatalf("ICE servers in /clients after opting out: %v", m["ice_servers"])
	}
}
