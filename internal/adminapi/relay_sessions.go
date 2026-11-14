package adminapi

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/bropines/rdpanel/internal/hbbs/control"
	"github.com/bropines/rdpanel/internal/httpx"
	"github.com/bropines/rdpanel/internal/relays"
	"github.com/bropines/rdpanel/internal/store"
)

// Active relay sessions with device labels (issue #39).
//
// hbbr "usage" reports one ip:port per relayed session. The panel knows the
// address each device last sent a heartbeat from, so a session can be
// labelled with the devices recently seen at that address. This is a hint,
// not an identification: devices behind one NAT share the address, and hbbr
// lists one side of each session only, so the other endpoint stays
// unlabelled. Direct (P2P) connections never pass a relay and never show up.

const (
	// relayUsageTimeout bounds the "usage" call to one relay in /relays/sessions.
	relayUsageTimeout = 5 * time.Second
	// deviceIPFreshness is how recent a device's last heartbeat must be for
	// its address to label a session: a relayed device is online and sends
	// heartbeats, while an old address may have been handed to someone else.
	deviceIPFreshness = 10 * time.Minute
	// devicesPerPeer caps the labels per session; devices_total has the count.
	devicesPerPeer = 5
)

// peerDevices are the labels of one relay peer.
type peerDevices struct {
	refs  []relayDeviceDTO
	total int
}

// relayDeviceDTO is components.schemas.RelayDeviceRef.
type relayDeviceDTO struct {
	ID         int64  `json:"id"`
	RustdeskID string `json:"rustdesk_id"`
	Label      string `json:"label"`
}

// relaySessionDTO is components.schemas.RelaySession.
type relaySessionDTO struct {
	RelayID   int64       `json:"relay_id"`
	RelayName string      `json:"relay_name"`
	RelayKind relays.Kind `json:"relay_kind"`
	RelayHost string      `json:"relay_host"`
	relayUsageDTO
}

// relayUnavailableDTO is components.schemas.RelaySessionsUnavailable.
type relayUnavailableDTO struct {
	RelayID   int64       `json:"relay_id"`
	RelayName string      `json:"relay_name"`
	RelayKind relays.Kind `json:"relay_kind"`
	RelayHost string      `json:"relay_host"`
	// Reason is "no_live_usage" (static relay, disconnected agent) or "error".
	Reason string `json:"reason"`
	Error  string `json:"error,omitempty"`
}

// peerIP returns the address part of an hbbr peer ("1.2.3.4:5", "[::1]:5"),
// with IPv4-mapped IPv6 addresses unmapped.
func peerIP(peer string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(peer); err == nil {
		return ap.Addr().Unmap(), true
	}
	if a, err := netip.ParseAddr(strings.Trim(peer, "[]")); err == nil {
		return a.Unmap(), true
	}
	return netip.Addr{}, false
}

// deviceLabel is the readable name of d: alias, hostname, else RustDesk ID.
func deviceLabel(d *store.Device) string {
	if s := strings.TrimSpace(d.Alias); s != "" {
		return s
	}
	if s := strings.TrimSpace(d.Hostname); s != "" {
		return s
	}
	return d.RustdeskID
}

// devicesByPeer maps each peer to the devices recently seen at its IP (keyed
// by the peer string). A failed lookup only drops the labels.
func (c *b2bCore) devicesByPeer(ctx context.Context, peers []string) map[string]peerDevices {
	byIP := map[netip.Addr][]string{}
	seenPeer := map[string]bool{}
	var keys []string
	for _, p := range peers {
		a, ok := peerIP(p)
		if !ok || seenPeer[p] {
			continue
		}
		seenPeer[p] = true
		if _, seen := byIP[a]; !seen {
			// last_seen_ip is stored as written by the heartbeat handler;
			// match the mapped IPv4 form too in case a proxy passed it so.
			keys = append(keys, a.String())
			if a.Is4() {
				keys = append(keys, netip.AddrFrom16(a.As16()).String())
			}
		}
		byIP[a] = append(byIP[a], p)
	}
	out := map[string]peerDevices{}
	if len(keys) == 0 {
		return out
	}
	since := c.d.Store.Now().Add(-deviceIPFreshness)
	found, err := c.d.Store.Devices.ListByLastSeenIPs(ctx, keys, since, devicesPerPeer)
	if err != nil {
		c.log.WarnContext(ctx, "relay sessions: devices by ip", slog.Any("err", err))
		return out
	}
	// Merge the plain and the IPv4-mapped spelling of one address, newest
	// heartbeat first, then cap.
	type merged struct {
		devs  []*store.Device
		total int
	}
	byAddr := map[netip.Addr]*merged{}
	for ip, at := range found {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		m := byAddr[a.Unmap()]
		if m == nil {
			m = &merged{}
			byAddr[a.Unmap()] = m
		}
		m.devs, m.total = append(m.devs, at.Devices...), m.total+at.Total
	}
	for a, m := range byAddr {
		sort.SliceStable(m.devs, func(i, j int) bool {
			ti, tj := heartbeatMs(m.devs[i]), heartbeatMs(m.devs[j])
			if ti != tj {
				return ti > tj
			}
			return m.devs[i].ID < m.devs[j].ID
		})
		refs := make([]relayDeviceDTO, 0, min(len(m.devs), devicesPerPeer))
		for _, d := range m.devs[:min(len(m.devs), devicesPerPeer)] {
			refs = append(refs, relayDeviceDTO{ID: d.ID, RustdeskID: d.RustdeskID, Label: deviceLabel(d)})
		}
		for _, p := range byIP[a] {
			out[p] = peerDevices{refs: refs, total: m.total}
		}
	}
	return out
}

func heartbeatMs(d *store.Device) int64 {
	if d.LastHeartbeatAt == nil {
		return 0
	}
	return d.LastHeartbeatAt.UnixMilli()
}

// usageDTO converts one hbbr usage row; devs comes from devicesByPeer.
func usageDTO(u control.RelayUsage, devs map[string]peerDevices) relayUsageDTO {
	pd := devs[u.Addr]
	if pd.refs == nil {
		pd.refs = []relayDeviceDTO{}
	}
	return relayUsageDTO{Peer: u.Addr, ElapsedS: int64(u.Elapsed / time.Second), TotalMB: u.TotalMB,
		HighestKbps: float64(u.HighestKbps), AvgKbps: float64(u.AvgKbps), CurrentKbps: float64(u.CurrentKbps),
		Devices: pd.refs, DevicesTotal: pd.total}
}

// relayUsageDTOs converts hbbr usage rows and attaches device labels.
func (c *b2bCore) relayUsageDTOs(ctx context.Context, usage []control.RelayUsage) []relayUsageDTO {
	devs := c.devicesByPeer(ctx, peersOf(usage))
	out := make([]relayUsageDTO, 0, len(usage))
	for _, u := range usage {
		out = append(out, usageDTO(u, devs))
	}
	return out
}

// handleRelaySessions is GET /relays/sessions: the live sessions of every
// relay that can report them, plus the relays that could not.
func (c *b2bCore) handleRelaySessions(w http.ResponseWriter, r *http.Request) {
	if !c.needRelays(w) {
		return
	}
	ctx := r.Context()
	views, _, err := c.d.Relays.List(ctx)
	if err != nil {
		c.relayErr(w, r, "list relays", err)
		return
	}
	type result struct {
		usage []control.RelayUsage
		err   error
	}
	results := make([]result, len(views))
	var wg sync.WaitGroup
	for i, v := range views {
		if v.Kind == relays.KindStatic {
			results[i].err = relays.ErrNoUsage
			continue
		}
		wg.Add(1)
		go func(i int, id int64) {
			defer wg.Done()
			cctx, cancel := context.WithTimeout(actorCtx(r), relayUsageTimeout)
			defer cancel()
			results[i].usage, results[i].err = c.d.Relays.Usage(cctx, id)
		}(i, v.ID)
	}
	wg.Wait()

	var all []control.RelayUsage
	for _, res := range results {
		all = append(all, res.usage...)
	}
	devs := c.devicesByPeer(ctx, peersOf(all))
	items := []relaySessionDTO{}
	unavailable := []relayUnavailableDTO{}
	for i, v := range views {
		res := results[i]
		if res.err != nil {
			u := relayUnavailableDTO{RelayID: v.ID, RelayName: v.Name, RelayKind: v.Kind, RelayHost: v.PublicHost, Reason: "no_live_usage"}
			if !errors.Is(res.err, relays.ErrNoUsage) {
				u.Reason, u.Error = "error", res.err.Error()
				c.log.WarnContext(ctx, "relay sessions: usage", slog.Int64("relay_id", v.ID), slog.Any("err", res.err))
			}
			unavailable = append(unavailable, u)
			continue
		}
		for _, u := range res.usage {
			items = append(items, relaySessionDTO{RelayID: v.ID, RelayName: v.Name, RelayKind: v.Kind, RelayHost: v.PublicHost,
				relayUsageDTO: usageDTO(u, devs)})
		}
	}
	httpx.WriteJSON(w, http.StatusOK, map[string]any{"checked_at": c.d.Store.Now().UTC(), "items": items, "unavailable": unavailable})
}

func peersOf(usage []control.RelayUsage) []string {
	out := make([]string, 0, len(usage))
	for _, u := range usage {
		out = append(out, u.Addr)
	}
	return out
}
