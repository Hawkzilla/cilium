// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"encoding/binary"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

// Symbol names of the Raptor trunk programs (sections in bpf/bpf_raptor.c).
// The tc filters derived from them (raptor_from_trunk-<if>, raptor_to_trunk-<if>)
// are what raptor-daemon's BPfFilterOnENI check looks for on the node.
const (
	symbolFromTrunk = "raptor_from_trunk"
	symbolToTrunk   = "raptor_to_trunk"

	// raptorFilterPrio is the tc priority of the Raptor filters. Fixed at 1:
	// - the replace key (link, parent, prio, protocol, handle) must stay
	//   deterministic so re-attaching replaces instead of duplicating;
	// - it must differ from option.Config.TCFilterPriority (the deployment
	//   sets bpf-filter-priority=10) so Cilium's own FilterReplace never
	//   collides with the Raptor filters on the same device;
	// - 1 evaluates before cil_from_netdev (pref 10), so the trunk ingress
	//   program pops the VLAN header before Cilium processes the packet.
	raptorFilterPrio = 1

	// rtnlGroupTC is RTNLGRP_TC (linux/rtnetlink.h enum value). nl.Subscribe
	// converts group numbers to the RTMGRP bitmask itself, so pass the enum
	// value, not RTMGRP_TC.
	rtnlGroupTC = 4

	// raptorReconcileInterval is the periodic safety net that restores filters
	// even if a netlink event was missed. Event-driven healing is the fast path.
	raptorReconcileInterval = 10 * time.Second

	// raptorResubscribeBackoff is how long to wait before re-subscribing to tc
	// filter events after a socket failure.
	raptorResubscribeBackoff = time.Second

	// raptorLoadRetryMin/Max bound the exponential backoff when the initial
	// compile/load of bpf_raptor.o fails (e.g. bpffs not yet mounted). The
	// watcher retries on each reconcile cycle until success.
	raptorLoadRetryMin = 5 * time.Second
	raptorLoadRetryMax = 60 * time.Second
)

// reinitializeRaptor makes sure bpf_raptor.o is compiled, loaded and attached
// to every trunk interface. Called from Reinitialize, i.e. during agent
// startup and every datapath reload. Load failures are non-fatal: the watcher
// retries in the background so the agent can still start.
func (l *loader) reinitializeRaptor(ctx context.Context) error {
	if !option.Config.EnableRaptor {
		return nil
	}

	if err := l.ensureRaptorLoaded(ctx); err != nil {
		l.logger.Warn("Raptor datapath not yet loaded, watcher will retry",
			logfields.Error, err)
		return nil
	}

	links, err := raptorTrunkLinks(l.logger)
	if err != nil {
		// Trunk enumeration is retried by the watcher's periodic reconcile.
		l.logger.Error("Failed to list raptor trunk links", logfields.Error, err)
		return nil
	}
	for _, link := range links {
		l.ensureRaptorLink(ctx, link, true)
	}
	return nil
}

// ensureRaptorLoaded compiles bpf_raptor.c and loads the object. On success
// the object (and its pinned maps) live for the agent's lifetime. On failure
// the error is cached with an exponential backoff; subsequent calls return
// the cached error until the backoff elapses, then retry.
func (l *loader) ensureRaptorLoaded(ctx context.Context) error {
	l.raptorMu.Lock()
	defer l.raptorMu.Unlock()

	if l.raptorObj != nil {
		return nil
	}
	if time.Now().Before(l.raptorNextRetry) {
		return l.raptorLoadErr
	}

	if err := l.loadRaptorObjects(ctx); err != nil {
		l.raptorLoadErr = err
		// Exponential backoff: double the interval each failure, capped at max.
		backoff := raptorLoadRetryMin
		if l.raptorNextRetry.After(time.Time{}) {
			backoff = time.Until(l.raptorNextRetry) * 2
			if backoff > raptorLoadRetryMax {
				backoff = raptorLoadRetryMax
			}
		}
		l.raptorNextRetry = time.Now().Add(backoff)
		l.logger.Warn("Failed to load raptor datapath, will retry",
			logfields.Error, err,
			logfields.Backoff, backoff)
		return err
	}

	l.raptorLoadErr = nil
	l.raptorNextRetry = time.Time{}
	return nil
}

// loadRaptorObjects compiles bpf_raptor.c and loads it with its maps pinned to
// the global bpffs directory (<bpffs>/tc/globals). That is how raptor-daemon
// feeds the IP/MAC/VLAN mappings into the datapath; existing pinned maps are
// reused so map contents survive an agent restart.
func (l *loader) loadRaptorObjects(ctx context.Context) error {
	if err := compileRaptor(ctx, l.logger); err != nil {
		return fmt.Errorf("compiling raptor program: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(filepath.Join(option.Config.StateDir, raptorObj))
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", raptorObj, err)
	}

	var obj raptorObjects
	commit, err := bpf.LoadAndAssign(l.logger, &obj, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
	})
	if err != nil {
		return fmt.Errorf("loading raptor eBPF collection: %w", err)
	}
	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	l.raptorObj = &obj
	return nil
}

// reconcileRaptorAll re-attaches the Raptor programs to every trunk interface.
// With force set the filters are replaced unconditionally, refreshing the
// program objects behind them (e.g. right after a daemon restart).
func (l *loader) reconcileRaptorAll(ctx context.Context, force bool) {
	if err := l.ensureRaptorLoaded(ctx); err != nil {
		l.logger.Error("Failed to load raptor datapath", logfields.Error, err)
		return
	}

	links, err := raptorTrunkLinks(l.logger)
	if err != nil {
		l.logger.Error("Failed to list raptor trunk links", logfields.Error, err)
		return
	}
	for _, link := range links {
		l.ensureRaptorLink(ctx, link, force)
	}
}

// reconcileRaptorIfindex restores the filters of one interface after a tc
// filter event. Re-attaching only what is missing keeps our own attach events
// from looping: a NEWTFILTER event finds the filter present and does nothing.
func (l *loader) reconcileRaptorIfindex(ctx context.Context, ifindex int) {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return // link is gone, nothing to attach
	}
	if !isRaptorTrunkLink(l.logger, link) {
		return
	}
	l.ensureRaptorLink(ctx, link, false)
}

// ensureRaptorLink makes sure both directions carry the Raptor filters on
// link. When force is set the filters are replaced unconditionally.
func (l *loader) ensureRaptorLink(ctx context.Context, link netlink.Link, force bool) {
	obj := l.raptorObj
	if obj == nil {
		return
	}

	if changed, err := l.ensureRaptorDirection(link, netlink.HANDLE_MIN_INGRESS, obj.FromTrunk, symbolFromTrunk, force); err != nil {
		l.logger.Error("Failed to attach raptor ingress program",
			logfields.Error, err,
			logfields.Interface, link.Attrs().Name,
		)
	} else if changed {
		l.logger.Info("Attached raptor ingress program",
			logfields.Interface, link.Attrs().Name,
		)
	}

	if changed, err := l.ensureRaptorDirection(link, netlink.HANDLE_MIN_EGRESS, obj.ToTrunk, symbolToTrunk, force); err != nil {
		l.logger.Error("Failed to attach raptor egress program",
			logfields.Error, err,
			logfields.Interface, link.Attrs().Name,
		)
	} else if changed {
		l.logger.Info("Attached raptor egress program",
			logfields.Interface, link.Attrs().Name,
		)
	}
}

// ensureRaptorDirection attaches prog under the given tc parent unless a
// healthy filter is already present. Stale copies of our own filter at a
// different priority are dropped so packets are not processed twice; filters
// that do not carry the Raptor name are never touched.
func (l *loader) ensureRaptorDirection(link netlink.Link, parent uint32, prog *ebpf.Program, progName string, force bool) (bool, error) {
	name := progName + "-" + link.Attrs().Name

	filters, err := safenetlink.FilterList(link, parent)
	if err != nil {
		return false, err
	}
	for _, f := range filters {
		bpfFilter, ok := f.(*netlink.BpfFilter)
		if !ok || bpfFilter.Name != name {
			continue
		}
		if bpfFilter.Priority == raptorFilterPrio && !force {
			return false, nil // present and healthy
		}
		if err := netlink.FilterDel(f); err != nil {
			return false, fmt.Errorf("deleting stale filter %s (prio %d): %w", name, bpfFilter.Priority, err)
		}
	}

	if err := replaceQdisc(link); err != nil {
		return false, fmt.Errorf("replacing clsact qdisc for interface %s: %w", link.Attrs().Name, err)
	}

	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    1,
			Protocol:  unix.ETH_P_ALL,
			Priority:  raptorFilterPrio,
		},
		Fd:           prog.FD(),
		Name:         name,
		DirectAction: true,
	}

	if err := netlink.FilterReplace(filter); err != nil {
		return false, fmt.Errorf("replacing tc filter for interface %s: %w", link.Attrs().Name, err)
	}

	l.logger.Info(
		"Program attached to device using legacy tc",
		logfields.ProgName, progName,
		logfields.Priority, filter.Attrs().Priority,
		logfields.Device, link.Attrs().Name,
	)
	return true, nil
}

// watchRaptor keeps the Raptor tc filters attached for the agent's lifetime.
// Filters are restored when netlink reports a tc filter change (RTNLGRP_TC
// events, the fast path), when a trunk link appears (link events; trunk
// interfaces are attached by neutron after node provisioning and can show up
// at any time), and by a periodic reconcile pass in case an event was missed.
func (l *loader) watchRaptor(ctx context.Context) error {
	// First pass force-replaces the filters so a restart also refreshes the
	// program objects behind them.
	l.reconcileRaptorAll(ctx, true)

	filterEvents := make(chan int, 64)
	go l.watchRaptorFilterEvents(ctx, filterEvents)

	linkUpdates := make(chan netlink.LinkUpdate, 16)
	if err := netlink.LinkSubscribe(linkUpdates, ctx.Done()); err != nil {
		// Non-fatal: the periodic reconcile keeps healing without link events.
		l.logger.Error("Failed to subscribe to link updates for raptor", logfields.Error, err)
	}

	ticker := time.NewTicker(raptorReconcileInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case u, ok := <-linkUpdates:
			if !ok {
				return nil
			}
			if isRaptorTrunkLink(l.logger, u.Link) {
				l.ensureRaptorLink(ctx, u.Link, true)
			}
		case ifindex := <-filterEvents:
			l.reconcileRaptorIfindex(ctx, ifindex)
		case <-ticker.C:
			l.reconcileRaptorAll(ctx, false)
		}
	}
}

// watchRaptorFilterEvents subscribes to RTNLGRP_TC and forwards the ifindex of
// every RTM_NEWTFILTER / RTM_DELTFILTER message so missing filters are
// restored immediately instead of waiting for the periodic reconcile.
func (l *loader) watchRaptorFilterEvents(ctx context.Context, events chan<- int) {
	for ctx.Err() == nil {
		sock, err := nl.Subscribe(unix.NETLINK_ROUTE, rtnlGroupTC)
		if err != nil {
			l.logger.Error("Failed to subscribe to tc filter events for raptor", logfields.Error, err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(raptorResubscribeBackoff):
			}
			continue
		}

		// Closing the socket unblocks a pending Receive on shutdown.
		done := make(chan struct{})
		go func() {
			select {
			case <-ctx.Done():
				sock.Close()
			case <-done:
			}
		}()

		l.receiveRaptorFilterEvents(ctx, sock, events)
		close(done)
		sock.Close()
	}
}

// receiveRaptorFilterEvents pumps tc filter events until the socket fails or
// ctx is cancelled. On failure the caller re-subscribes.
func (l *loader) receiveRaptorFilterEvents(ctx context.Context, sock *nl.NetlinkSocket, events chan<- int) {
	for {
		msgs, _, err := sock.Receive()
		if err != nil {
			if ctx.Err() == nil {
				l.logger.Error("Failed to receive tc filter events for raptor", logfields.Error, err)
			}
			return
		}
		for _, msg := range msgs {
			switch msg.Header.Type {
			case unix.RTM_NEWTFILTER, unix.RTM_DELTFILTER:
			default:
				continue
			}
			ifindex := tcmsgIfindex(msg.Data)
			if ifindex <= 0 {
				continue
			}
			select {
			case events <- ifindex:
			case <-ctx.Done():
				return
			}
		}
	}
}

// tcmsgIfindex extracts tcm_ifindex from a struct tcmsg payload
// (linux/pkt_sched.h: u8 family, u8 pad, u16 pad, int ifindex, ...). Netlink
// messages use host byte order.
func tcmsgIfindex(data []byte) int {
	if len(data) < 8 {
		return 0
	}
	return int(int32(binary.NativeEndian.Uint32(data[4:8])))
}

// raptorTrunkLinks returns every Raptor trunk interface: virtio devices other
// than the one holding the IPv4 default route. Trunk parent ports carry no IP
// address by design, so selection must not depend on address presence.
func raptorTrunkLinks(logger *slog.Logger) ([]netlink.Link, error) {
	links, err := safenetlink.LinkList()
	if err != nil {
		return nil, err
	}
	var out []netlink.Link
	for _, link := range links {
		if isRaptorTrunkLink(logger, link) {
			out = append(out, link)
			logger.Info("Found raptor trunk interface", logfields.Interface, link.Attrs().Name)
		}
	}
	return out, nil
}

// isRaptorTrunkLink reports whether link is a Raptor trunk interface.
func isRaptorTrunkLink(logger *slog.Logger, link netlink.Link) bool {
	if link.Type() != "device" {
		return false
	}

	driver, err := getLinkDriver(link.Attrs().Name)
	if err != nil || !isRaptorTrunkDriver(driver) {
		return false
	}

	main, err := getMainNIC()
	if err != nil {
		logger.Warn("Failed to get main network interface for raptor", logfields.Error, err)
		return false
	}
	return link.Attrs().Name != main
}

// isRaptorTrunkDriver matches the virtio drivers Raptor trunk interfaces are
// backed by.
func isRaptorTrunkDriver(driver string) bool {
	return driver == "virtio_pci" || driver == "virtio_net"
}

// getLinkDriver returns the driver name bound to the interface, or "" when the
// interface has no device (e.g. veth).
func getLinkDriver(ifaceName string) (string, error) {
	driverPath := fmt.Sprintf("/sys/class/net/%s/device/driver", ifaceName)
	target, err := filepath.EvalSymlinks(driverPath)
	if err != nil {
		if os.IsNotExist(err) {
			return "", nil
		}
		return "", err
	}
	return filepath.Base(target), nil
}

// getMainNIC returns the name of the interface holding the IPv4 default route,
// or "" when there is none yet.
func getMainNIC() (string, error) {
	routes, err := netlink.RouteList(nil, netlink.FAMILY_V4)
	if err != nil {
		return "", err
	}
	for _, route := range routes {
		// IPv4 default route: 0.0.0.0/0
		if route.Dst != nil && route.Dst.String() == "0.0.0.0/0" {
			link, err := netlink.LinkByIndex(route.LinkIndex)
			if err != nil {
				continue // route may race with link removal
			}
			return link.Attrs().Name, nil
		}
	}
	return "", nil
}

// registerRaptorWatcher starts the Raptor datapath self-healing job.
func registerRaptorWatcher(p Params, l *loader) {
	p.JobGroup.Add(job.OneShot("raptor-datapath-watcher", func(ctx context.Context, _ cell.Health) error {
		if !option.Config.EnableRaptor {
			return nil
		}
		return l.watchRaptor(ctx)
	}))
}
