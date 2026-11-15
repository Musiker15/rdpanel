package adminapi

import (
	"net/http"
	"testing"
	"time"

	"github.com/bropines/rdpanel/internal/relays"
	"github.com/bropines/rdpanel/internal/store"
)

func TestPeerIP(t *testing.T) {
	for in, want := range map[string]string{
		"1.2.3.4:5555":          "1.2.3.4",
		"[::1]:6000":            "::1",
		"[::ffff:1.2.3.4]:5555": "1.2.3.4",
		"10.0.0.1":              "10.0.0.1",
	} {
		if a, ok := peerIP(in); !ok || a.String() != want {
			t.Errorf("peerIP(%q) = %v %v, want %s", in, a, ok, want)
		}
	}
	if _, ok := peerIP("not-an-ip:1"); ok {
		t.Error("garbage parsed")
	}
}

// relayDevices returns the labels attached to a usage/session row.
func relayDevices(t *testing.T, row map[string]any) []string {
	t.Helper()
	list, ok := row["devices"].([]any)
	if !ok {
		t.Fatalf("devices missing or not a list: %v", row)
	}
	out := []string{}
	for _, d := range list {
		out = append(out, d.(map[string]any)["label"].(string))
	}
	return out
}

func TestRelaySessions(t *testing.T) {
	e := newRelayEnv(t)
	admin, _ := e.as("root", store.RoleAdmin)
	user, _ := e.as("bob", store.RoleUser)

	// The fake hbbr reports 1.2.3.4:5555 and [::1]:6000.
	mkDev := func(id, alias, host, ip string) {
		d := &store.Device{RustdeskID: id, Alias: alias, Hostname: host}
		if err := e.st.Devices.Create(e.ctx, d); err != nil {
			t.Fatal(err)
		}
		if _, err := e.st.Devices.TouchHeartbeat(e.ctx, d.ID, ip, time.Second); err != nil {
			t.Fatal(err)
		}
	}
	mkDev("999999999", "Old laptop", "", "1.2.3.4") // last seen an hour ago: no label
	e.clk.advance(time.Hour)
	mkDev("111111111", "Office laptop", "OFFICE-PC", "1.2.3.4")
	e.clk.advance(time.Second)
	mkDev("222222222", "", "THINKPAD", "1.2.3.4") // same NAT address, seen last
	mkDev("333333333", "", "", "::1")
	mkDev("444444444", "Elsewhere", "", "9.9.9.9")

	code, m, _ := admin.do(http.MethodGet, "/server/relay-usage", nil)
	want(t, "relay usage", code, 200, m)
	l := b2bItems(m)
	if len(l) != 2 || l[0]["peer"] != "1.2.3.4:5555" {
		t.Fatalf("relay usage: %v", m)
	}
	if got := relayDevices(t, l[0]); len(got) != 2 || got[0] != "THINKPAD" || got[1] != "Office laptop" || b2bNum(l[0]["devices_total"]) != 2 {
		t.Fatalf("labels for 1.2.3.4 (most recent first, stale one left out): %v %v", got, l[0]["devices_total"])
	}
	if got := relayDevices(t, l[1]); len(got) != 1 || got[0] != "333333333" {
		t.Fatalf("labels for ::1 (falls back to the RustDesk ID): %v", got)
	}

	for _, nr := range []relays.NewRelay{
		{Name: "local", Kind: relays.KindLocal, PublicHost: "relay-a.example.com:21117", Weight: 1, InRotation: true, Health: relays.HealthActive},
		{Name: "partner", Kind: relays.KindStatic, PublicHost: "relay-b.example.com:21117", Weight: 1, InRotation: true, Health: relays.HealthActive},
		{Name: "branch", Kind: relays.KindAgent, PublicHost: "relay-c.example.com:21117", Weight: 1, Health: relays.HealthPending},
	} {
		if _, err := e.rstore.Create(e.ctx, nr); err != nil {
			t.Fatal(err)
		}
	}

	code, m, _ = user.do(http.MethodGet, "/relays/sessions", nil)
	wantErr(t, "user sessions", code, 403, m, "forbidden")

	code, m, _ = admin.do(http.MethodGet, "/relays/sessions", nil)
	want(t, "sessions", code, 200, m)
	items := b2bItems(m)
	if len(items) != 2 || m["checked_at"] == nil {
		t.Fatalf("sessions: %v", m)
	}
	s := items[0]
	if s["relay_name"] != "local" || s["relay_kind"] != "local" || s["relay_host"] != "relay-a.example.com:21117" ||
		s["peer"] != "1.2.3.4:5555" || s["total_mb"] != 12.5 {
		t.Fatalf("session: %v", s)
	}
	if got := relayDevices(t, s); len(got) != 2 {
		t.Fatalf("session labels: %v", got)
	}
	un, _ := m["unavailable"].([]any)
	if len(un) != 2 {
		t.Fatalf("unavailable: %v", m["unavailable"])
	}
	for _, x := range un {
		u := x.(map[string]any)
		if u["reason"] != "no_live_usage" || (u["relay_name"] != "partner" && u["relay_name"] != "branch") {
			t.Fatalf("unavailable relay: %v", u)
		}
	}
}
