package auth

import (
	"strconv"
	"time"
)

// AttemptReserver bounds attempts per key before they are checked, unlike the
// failure backoff, which only counts failures already recorded: a burst of
// parallel requests all pass Allow before the first one fails. Backoff
// implements it.
type AttemptReserver interface {
	// Reserve counts one attempt for key in a sliding window of window. It
	// reports false (and how long until a slot frees) when limit attempts are
	// already in the window; the attempt is then not counted.
	Reserve(key string, limit int, window time.Duration) (ok bool, retryAfter time.Duration)
	// Release forgets the attempts counted for key (after a success).
	Release(key string)
}

// Second-factor codes (TOTP, e-mailed login codes) per user, across the panel
// and the client API: 10 in 15 minutes. With a TOTP window of three valid codes
// that leaves well under 1% a day to guessing, on top of the failure backoff.
const (
	SecondFactorLimit  = 10
	SecondFactorWindow = 15 * time.Minute
)

func secondFactorKey(userID int64) string { return "2fa.user:" + strconv.FormatInt(userID, 10) }

// ReserveSecondFactor counts a second-factor attempt for userID before the
// code is checked. With a Limiter that does not reserve it always succeeds.
func ReserveSecondFactor(l Limiter, userID int64) (bool, time.Duration) {
	r, ok := l.(AttemptReserver)
	if !ok {
		return true, 0
	}
	return r.Reserve(secondFactorKey(userID), SecondFactorLimit, SecondFactorWindow)
}

// ReleaseSecondFactor clears userID's second-factor attempts after a success.
func ReleaseSecondFactor(l Limiter, userID int64) {
	if r, ok := l.(AttemptReserver); ok {
		r.Release(secondFactorKey(userID))
	}
}

var _ AttemptReserver = (*Backoff)(nil)

// Reserve implements AttemptReserver.
func (b *Backoff) Reserve(key string, limit int, window time.Duration) (bool, time.Duration) {
	b.mu.Lock()
	defer b.mu.Unlock()
	now := b.now()
	if b.attempts == nil {
		b.attempts = make(map[string][]time.Time)
	}
	kept := b.attempts[key][:0]
	for _, t := range b.attempts[key] {
		if now.Sub(t) < window {
			kept = append(kept, t)
		}
	}
	if len(kept) >= limit {
		b.attempts[key] = kept
		return false, window - now.Sub(kept[0])
	}
	b.attempts[key] = append(kept, now)
	return true, 0
}

// Release implements AttemptReserver.
func (b *Backoff) Release(key string) {
	b.mu.Lock()
	delete(b.attempts, key)
	b.mu.Unlock()
}

// pruneAttempts drops attempt windows with nothing newer than maxAge; b.mu held.
func (b *Backoff) pruneAttempts(now time.Time, maxAge time.Duration) {
	for k, ts := range b.attempts {
		if len(ts) == 0 || now.Sub(ts[len(ts)-1]) >= maxAge {
			delete(b.attempts, k)
		}
	}
}
