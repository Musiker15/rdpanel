package httpx

import (
	"net/http/httptest"
	"testing"
)

func TestClientIPKey(t *testing.T) {
	for remote, want := range map[string]string{
		"203.0.113.7:4000":               "203.0.113.7",
		"[::ffff:203.0.113.7]:4000":      "203.0.113.7",
		"[2001:db8:1:2:aaaa::1]:4000":    "2001:db8:1:2::/64",
		"[2001:db8:1:2:ffff:ffff::]:443": "2001:db8:1:2::/64",
	} {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = remote
		if got := ClientIPKey(r); got != want {
			t.Errorf("%s: %q, want %q", remote, got, want)
		}
	}
}
