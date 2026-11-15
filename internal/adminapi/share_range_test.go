package adminapi

import "testing"

// A download counts whenever the response can include byte 0; only resumed
// downloads are free.
func TestRangeFromStart(t *testing.T) {
	const size = 1000
	counted := []string{"", "bytes=0-", "bytes=00-", "bytes=0-99", "bytes=-1000", "bytes=-5000",
		"bytes=500-,0-0", "bytes= 0 - 10", "items=5-", "bytes=", "bytes=x-", "bytes=5"}
	for _, h := range counted {
		if !rangeFromStart(h, size) {
			t.Errorf("%q: not counted", h)
		}
	}
	for _, h := range []string{"bytes=1-", "bytes=500-999", "bytes=-999", "bytes=10-20,30-"} {
		if rangeFromStart(h, size) {
			t.Errorf("%q: counted as a new download", h)
		}
	}
}
