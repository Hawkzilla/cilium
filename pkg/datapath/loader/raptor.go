// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package loader

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/hive/cell"
	"github.com/cilium/hive/job"
	"github.com/vishvananda/netlink"

	"github.com/cilium/cilium/pkg/bpf"
	"github.com/cilium/cilium/pkg/datapath/linux/safenetlink"
	"github.com/cilium/cilium/pkg/logging"
	"github.com/cilium/cilium/pkg/logging/logfields"
	"github.com/cilium/cilium/pkg/option"
)

const (
	symbolFromTrunk = "raptor_from_trunk"
	symbolToTrunk   = "raptor_to_trunk"
)

// virtio drivers Raptor trunk interfaces are backed by.
func isRaptorTrunkDriver(driver string) bool {
	return driver == "virtio_pci" || driver == "virtio_net"
}

// reinitializeRaptor compiles bpf_raptor.c and attaches its programs to every
// trunk interface, i.e. all virtio devices except the one holding the default
// route.
func (l *loader) reinitializeRaptor(ctx context.Context) error {
	if !option.Config.EnableRaptor {
		return nil
	}

	links, err := safenetlink.LinkList()
	if err != nil {
		return err
	}

	mainInterface, err := getMainNIC()
	if err != nil {
		logging.Fatal(l.logger, "failed to get main network interface", logfields.Error, err)
	}

	var attach []netlink.Link
	for _, link := range links {
		if link.Type() != "device" || mainInterface == link.Attrs().Name {
			continue
		}

		driver, err := getLinkDriver(link.Attrs().Name)
		if err != nil {
			logging.Fatal(l.logger, "failed to get link driver",
				logfields.Error, err,
				logfields.Link, link.Attrs().Name,
			)
		}
		if isRaptorTrunkDriver(driver) {
			attach = append(attach, link)
			l.logger.Info("found virtio-pci interface", logfields.Device, link.Attrs().Name)
		}
	}

	// No trunk interface yet is valid, e.g. before the VPC attaches one.
	if len(attach) == 0 {
		return nil
	}

	if err := replaceRaptorDatapath(ctx, l.logger, attach); err != nil {
		return fmt.Errorf("failed to replace raptor datapath: %w", err)
	}

	return nil
}

// replaceRaptorDatapath loads bpf_raptor.o and attaches its ingress and egress
// programs to the given links. The ELF's maps are pinned to the global bpffs
// path, which is how the Raptor agent feeds the IP/MAC/VLAN mappings into the
// datapath.
func replaceRaptorDatapath(ctx context.Context, logger *slog.Logger, links []netlink.Link) error {
	if err := compileRaptor(ctx, logger); err != nil {
		return fmt.Errorf("compiling raptor program: %w", err)
	}

	spec, err := ebpf.LoadCollectionSpec(raptorObj)
	if err != nil {
		return fmt.Errorf("loading eBPF ELF %s: %w", raptorObj, err)
	}

	var obj raptorObjects
	commit, err := bpf.LoadAndAssign(logger, &obj, spec, &bpf.CollectionOptions{
		CollectionOptions: ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{PinPath: bpf.TCGlobalsPath()},
		},
	})
	if err != nil {
		return err
	}
	defer obj.Close()

	var errs error
	for _, link := range links {
		linkDir := bpffsDeviceLinksDir(bpf.CiliumPath(), link)

		// Attaching one interface may fail, keep attaching to the others.
		if err := attachSKBProgram(logger, link, obj.FromTrunk, symbolFromTrunk,
			linkDir, netlink.HANDLE_MIN_INGRESS, option.Config.EnableTCX); err != nil {
			errs = errors.Join(errs, fmt.Errorf("interface %s ingress: %w", link.Attrs().Name, err))
			continue
		}

		if err := attachSKBProgram(logger, link, obj.ToTrunk, symbolToTrunk,
			linkDir, netlink.HANDLE_MIN_EGRESS, option.Config.EnableTCX); err != nil {
			errs = errors.Join(errs, fmt.Errorf("interface %s egress: %w", link.Attrs().Name, err))
			continue
		}

		logger.Info("Raptor network program (re)loaded", logfields.Interface, link.Attrs().Name)
	}

	if errs != nil {
		return fmt.Errorf("failed to load raptor program: %w", errs)
	}

	if err := commit(); err != nil {
		return fmt.Errorf("committing bpf pins: %w", err)
	}

	return nil
}

// registerRaptorLinkWatcher reattaches the raptor programs to trunk interfaces
// that show up after the initial datapath initialization.
func registerRaptorLinkWatcher(p Params) {
	p.JobGroup.Add(job.OneShot("raptor-link-watcher", func(ctx context.Context, _ cell.Health) error {
		if !option.Config.EnableRaptor {
			return nil
		}

		updates := make(chan netlink.LinkUpdate)
		if err := netlink.LinkSubscribe(updates, ctx.Done()); err != nil {
			return fmt.Errorf("subscribing to link changes: %w", err)
		}

		for {
			select {
			case <-ctx.Done():
				return nil
			case u, ok := <-updates:
				if !ok {
					return nil
				}
				if !isVirtioLink(p.Logger, u) {
					continue
				}

				name := u.Attrs().Name
				p.Logger.Info("Virtio device changed, reinitializing raptor",
					logfields.Device, name,
				)
				if err := replaceRaptorDatapath(ctx, p.Logger, []netlink.Link{u.Link}); err != nil {
					p.Logger.Warn("Failed to reinitialize raptor",
						logfields.Error, err,
						logfields.Device, name,
					)
				}
			}
		}
	}))
}

func isVirtioLink(logger *slog.Logger, update netlink.LinkUpdate) bool {
	if update.Type() != "device" {
		return false
	}

	driver, err := getLinkDriver(update.Attrs().Name)
	if err != nil {
		return false
	}

	if isRaptorTrunkDriver(driver) {
		addrList, err := netlink.AddrList(update.Link, netlink.FAMILY_V4)
		if err != nil {
			logging.Fatal(logger, "Failed to list addresses with virtio", logfields.Error, err)
		} else {
			for _, addr := range addrList {
				if addr.IPNet.IP.To4().String() == os.Getenv("K8S_NODE_IP") {
					return false
				}
			}
		}

		return true
	}

	return false
}

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
				return "", err
			}
			return link.Attrs().Name, nil
		}
	}
	return "", fmt.Errorf("default route not found")
}
