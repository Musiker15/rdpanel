package clientopts

import (
	"context"
	"regexp"
	"strconv"
)

// RustDesk 1.5.3 (rustdesk/rustdesk#16696) refuses a set of options in
// heartbeat strategies, ice-servers among them: the panel still sends it (older
// clients use it), but 1.5.3 and later keep their own value and only log
// "Rejected heartbeat strategy options". Installing with
// `rustdesk --option ice-servers …` is what still reaches them (InInstall).
var strategyICEIgnoredFrom = [3]int{1, 5, 3}

var versionParts = regexp.MustCompile(`\d+`)

// IgnoresStrategyICE reports whether a client of version v ("1.5.3",
// "1.5.3-1") ignores ice-servers sent in a heartbeat strategy. An empty or
// unparsable version is reported as not ignoring it.
func IgnoresStrategyICE(v string) bool {
	parts := versionParts.FindAllString(v, 3)
	if len(parts) < 2 {
		return false
	}
	for i, want := range strategyICEIgnoredFrom {
		got := 0
		if i < len(parts) {
			got, _ = strconv.Atoi(parts[i])
		}
		if got != want {
			return got > want
		}
	}
	return true
}

// DevicesIgnoringICE counts the devices whose last reported client version
// ignores ice-servers from strategies.
func (s *Service) DevicesIgnoringICE(ctx context.Context) (int, error) {
	if s.st == nil || s.st.Devices == nil {
		return 0, nil
	}
	counts, err := s.st.Devices.CountByClientVersion(ctx)
	if err != nil {
		return 0, err
	}
	n := 0
	for v, c := range counts {
		if IgnoresStrategyICE(v) {
			n += c
		}
	}
	return n, nil
}
