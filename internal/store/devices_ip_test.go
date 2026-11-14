package store

import (
	"context"
	"testing"
	"time"
)

func TestDevicesListByLastSeenIPs(t *testing.T) {
	s, clk := newSecretStore(t)
	ctx := context.Background()
	mk := func(id, ip string) *Device {
		d := &Device{RustdeskID: id}
		if err := s.Devices.Create(ctx, d); err != nil {
			t.Fatal(err)
		}
		if ip != "" {
			if _, err := s.Devices.TouchHeartbeat(ctx, d.ID, ip, time.Second); err != nil {
				t.Fatal(err)
			}
		}
		clk.advance(time.Minute)
		return d
	}
	stale := mk("100000000", "192.0.2.10") // its IP may belong to someone else by now
	clk.advance(time.Hour)
	since := clk.now()
	a := mk("111111111", "192.0.2.10")
	b := mk("222222222", "192.0.2.10") // same NAT address as a, seen later
	c := mk("333333333", "2001:db8::1")
	mk("444444444", "192.0.2.99")
	mk("555555555", "")

	got, err := s.Devices.ListByLastSeenIPs(ctx, []string{"192.0.2.10", "2001:db8::1", "198.51.100.1"}, since, 5)
	if err != nil {
		t.Fatal(err)
	}
	nat := got["192.0.2.10"]
	if len(got) != 2 || nat.Total != 2 || len(nat.Devices) != 2 || nat.Devices[0].ID != b.ID || nat.Devices[1].ID != a.ID {
		t.Fatalf("most recent first, stale device %d left out: %+v", stale.ID, got)
	}
	if v6 := got["2001:db8::1"]; v6.Total != 1 || len(v6.Devices) != 1 || v6.Devices[0].ID != c.ID {
		t.Fatalf("v6: %+v", v6)
	}

	// The cap keeps the newest per address but still counts all of them.
	got, err = s.Devices.ListByLastSeenIPs(ctx, []string{"192.0.2.10", "2001:db8::1"}, since, 1)
	if err != nil {
		t.Fatal(err)
	}
	if nat := got["192.0.2.10"]; nat.Total != 2 || len(nat.Devices) != 1 || nat.Devices[0].ID != b.ID {
		t.Fatalf("capped: %+v", nat)
	}
	if v6 := got["2001:db8::1"]; len(v6.Devices) != 1 {
		t.Fatalf("one large address must not push out others: %+v", got)
	}

	if got, err := s.Devices.ListByLastSeenIPs(ctx, nil, since, 5); err != nil || len(got) != 0 {
		t.Fatalf("no ips: %v %v", got, err)
	}
}
