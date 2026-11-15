package auth

import (
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestReserveBoundsAttemptsBeforeTheyFail(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	b := NewBackoff(DefaultBackoffConfig, func() time.Time { return now })

	// A parallel burst: only SecondFactorLimit get through, whatever the
	// failure backoff has seen so far (nothing).
	var passed atomic.Int32
	var wg sync.WaitGroup
	for range 100 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ok, _ := ReserveSecondFactor(b, 7); ok {
				passed.Add(1)
			}
		}()
	}
	wg.Wait()
	if got := passed.Load(); got != SecondFactorLimit {
		t.Fatalf("%d attempts passed, want %d", got, SecondFactorLimit)
	}
	ok, wait := ReserveSecondFactor(b, 7)
	if ok || wait != SecondFactorWindow {
		t.Fatalf("over the limit: %v %v", ok, wait)
	}
	// Another user is not affected.
	if ok, _ := ReserveSecondFactor(b, 8); !ok {
		t.Fatal("user 8 refused")
	}
	// The window slides.
	now = now.Add(SecondFactorWindow)
	if ok, _ := ReserveSecondFactor(b, 7); !ok {
		t.Fatal("still refused after the window")
	}
	// A success clears the count.
	for range SecondFactorLimit {
		ReserveSecondFactor(b, 9)
	}
	ReleaseSecondFactor(b, 9)
	if ok, _ := ReserveSecondFactor(b, 9); !ok {
		t.Fatal("refused after a release")
	}
	// Old windows are pruned.
	now = now.Add(2 * time.Hour)
	b.Prune()
	if len(b.attempts) != 0 {
		t.Fatalf("attempt windows left after prune: %d", len(b.attempts))
	}
}
