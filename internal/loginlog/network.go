package loginlog

import (
	"context"
	"net/http"
	"time"

	"github.com/bropines/rdpanel/internal/httpx"
	"github.com/bropines/rdpanel/internal/store"
)

// KnownNetworkWindow is how long a successful sign-in makes its network
// (IPv4 address, IPv6 /64) known for the per-name login backoff.
const KnownNetworkWindow = 30 * 24 * time.Hour

// KnownNetwork reports whether u signed in successfully from the client's
// network within KnownNetworkWindow. Errors count as unknown.
func KnownNetwork(ctx context.Context, st *store.Store, u *store.User, r *http.Request) bool {
	key := httpx.ClientIPKey(r)
	if u == nil || key == "" {
		return false
	}
	ok, err := st.LoginEvents.SucceededFrom(ctx, u.ID, st.Now().Add(-KnownNetworkWindow),
		func(ip string) bool { return httpx.IPKeyString(ip) == key })
	return err == nil && ok
}
