package auth

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Login and password reset hash on every request that passes the backoff,
// and the backoff only counts failures that already happened. A burst of
// parallel requests must not run more argon2id computations at once than
// argon2Slots allows, or each one allocates Params.Memory on top.
func TestArgon2ConcurrencyIsCapped(t *testing.T) {
	var inflight, peak atomic.Int32
	orig := idKey
	idKey = func(password, salt []byte, time_, memory uint32, threads uint8, keyLen uint32) []byte {
		n := inflight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inflight.Add(-1)
		return orig(password, salt, 1, 8, 1, keyLen)
	}
	t.Cleanup(func() { idKey = orig })

	h := &Hasher{Params: Argon2Params{Memory: 8, Time: 1, Threads: 1, SaltLen: 16, KeyLen: 32}}
	stored, _, err := h.Hash("seed")
	if err != nil {
		t.Fatal(err)
	}
	limit := int32(cap(argon2Slots))
	var wg sync.WaitGroup
	for i := range 4 * cap(argon2Slots) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if i%2 == 0 {
				_, _, _ = h.Hash("password")
			} else {
				h.Verify(stored, "wrong")
			}
		}()
	}
	wg.Wait()
	if got := peak.Load(); got > limit {
		t.Fatalf("%d argon2id computations ran at once, want at most %d", got, limit)
	} else if got < 2 {
		t.Fatalf("peak %d: the computations did not run in parallel at all", got)
	}
}
