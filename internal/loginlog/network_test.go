package loginlog_test

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/bropines/rdpanel/internal/db/dbtest"
	"github.com/bropines/rdpanel/internal/loginlog"
	"github.com/bropines/rdpanel/internal/store"
)

func TestKnownNetwork(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	st := store.New(dbtest.Open(t)).WithClock(func() time.Time { return now })
	ctx := context.Background()
	u := &store.User{Username: "admin", Role: store.RoleAdmin}
	if err := st.Users.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	record := func(ip, result string, at time.Time) {
		t.Helper()
		if err := st.LoginEvents.Record(ctx, &store.LoginEvent{UserID: &u.ID, Method: store.LoginMethodPassword,
			Result: result, IP: ip, CreatedAt: at}); err != nil {
			t.Fatal(err)
		}
	}
	record("198.51.100.7", store.LoginSuccess, now.Add(-24*time.Hour))
	record("2001:db8:1:2::10", store.LoginSuccess, now.Add(-time.Hour))
	record("203.0.113.9", store.LoginFailure, now.Add(-time.Hour))
	record("192.0.2.1", store.LoginSuccess, now.Add(-loginlog.KnownNetworkWindow-time.Hour))

	req := func(remote string) bool {
		r := httptest.NewRequest("POST", "/", nil)
		r.RemoteAddr = remote
		return loginlog.KnownNetwork(ctx, st, u, r)
	}
	for remote, want := range map[string]bool{
		"198.51.100.7:1000":        true,  // same address
		"198.51.100.8:1000":        false, // IPv4: the address, not a range
		"[2001:db8:1:2::abcd]:443": true,  // same IPv6 /64
		"[2001:db8:1:3::10]:443":   false,
		"203.0.113.9:1000":         false, // failures do not count
		"192.0.2.1:1000":           false, // too long ago
	} {
		if got := req(remote); got != want {
			t.Errorf("%s: %v, want %v", remote, got, want)
		}
	}
	if loginlog.KnownNetwork(ctx, st, nil, httptest.NewRequest("POST", "/", nil)) {
		t.Error("unknown user on a known network")
	}
}
