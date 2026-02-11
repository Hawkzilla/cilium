// SPDX-License-Identifier: Apache-2.0
// Copyright Authors of Cilium

package eni

import (
	"context"
	"errors"
	"fmt"
	"github.com/cilium/cilium/pkg/defaults"
	"github.com/cilium/cilium/pkg/ipam"
	"github.com/cilium/cilium/pkg/ipam/stats"
	ipamTypes "github.com/cilium/cilium/pkg/ipam/types"
	v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/lock"
	"github.com/cilium/cilium/pkg/math"
	"github.com/cilium/cilium/pkg/openstack/eni/limits"
	eniTypes "github.com/cilium/cilium/pkg/openstack/eni/types"
	"github.com/cilium/cilium/pkg/openstack/utils"
	"github.com/sirupsen/logrus"
)

// The following error constants represent the error conditions for
// CreateInterface without additional context embedded in order to make them
// usable for metrics accounting purposes.
const (
	errUnableToDetermineLimits   = "unable to determine limits"
	unableToDetermineLimits      = "unableToDetermineLimits"
	errUnableToGetSecurityGroups = "unable to get security groups"
	unableToGetSecurityGroups    = "unableToGetSecurityGroups"
	errUnableToCreateENI         = "unable to create ENI"
	unableToCreateENI            = "unableToCreateENI"
	errUnableToAttachENI         = "unable to attach ENI"
	unableToAttachENI            = "unableToAttachENI"
	unableToFindSubnet           = "unableToFindSubnet"
	unableToTagENI               = "unableToTagENI"
)

const (
	maxENIIPCreate = 10

	maxENIPerNode = 50
)

type Node struct {
	// node contains the general purpose fields of a node
	node *ipam.Node

	// mutex protects members below this field
	mutex lock.RWMutex

	// enis is the list of ENIs attached to the node indexed by ENI ID.
	// Protected by Node.mutex.
	enis map[string]eniTypes.ENI

	// k8sObj is the CiliumNode custom resource representing the node
	k8sObj *v2.CiliumNode

	// manager is the ecs node manager responsible for this node
	manager *InstancesManager

	// instanceID of the node
	instanceID string

	// poolsEnis is the list of eniIDs that belong to the ipam.Pool
	poolsEnis map[ipam.Pool][]string
}

// UpdatedNode is called when an update to the CiliumNode is received.
func (n *Node) UpdatedNode(obj *v2.CiliumNode) {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.k8sObj = obj
}

// PopulateStatusFields fills in the status field of the CiliumNode custom
// resource with ENI specific information
func (n *Node) PopulateStatusFields(resource *v2.CiliumNode) {
	resource.Status.OpenStack.ENIs = map[string]eniTypes.ENI{}

	n.manager.ForeachInstance(n.node.InstanceID(),
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if ok {
				resource.Status.OpenStack.ENIs[interfaceID] = *e.DeepCopy()
			}
			return nil
		})
	return
}

// CreateInterface creates an additional interface with the instance and
// attaches it to the instance as specified by the CiliumNode. neededAddresses
// of secondary IPs are assigned to the interface up to the maximum number of
// addresses as allowed by the instance.
func (n *Node) CreateInterface(ctx context.Context, allocation *ipam.AllocationAction, scopedLog *logrus.Entry, pool ipam.Pool) (int, string, error) {
	limits, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return 0, unableToDetermineLimits, fmt.Errorf(errUnableToDetermineLimits)
	}

	n.mutex.RLock()
	//if len(n.poolsEnis[pool]) > 0 {
	//	return 0, errUnableToCreateENI, errors.New("no more pool eni slot")
	//}
	resource := *n.k8sObj
	n.mutex.RUnlock()

	// Must allocate secondary ENI IPs as needed, up to ENI instance limit
	toAllocate := math.IntMin(allocation.MaxIPsToAllocate, limits.IPv4)
	toAllocate = math.IntMin(maxENIIPCreate, toAllocate) // in first alloc no more than 10
	// Validate whether request has already been fulfilled in the meantime
	if toAllocate == 0 {
		return 0, "", nil
	}

	subnet := n.findSuitableSubnet(resource.Spec.OpenStack, limits, pool.SubnetId())
	if subnet == nil {
		return 0,
			unableToFindSubnet,
			fmt.Errorf(
				"No matching subnet available for interface creation (AZ=%s SubnetID=%s)",
				resource.Spec.OpenStack.AvailabilityZone,
				pool.SubnetId(),
			)
	}
	allocation.PoolID = ipamTypes.PoolID(subnet.ID)

	scopedLog = scopedLog.WithFields(logrus.Fields{
		"subnet":     subnet.ID,
		"toAllocate": toAllocate,
	})
	scopedLog.Info("No more IPs available, creating new ENI")

	instanceID := n.node.InstanceID()
	n.mutex.Lock()
	defer n.mutex.Unlock()

	if limits.Adapters-len(n.enis) <= 0 {
		return 0, errUnableToCreateENI, errors.New("no more eni slot")
	}

	// use configured "--openstack-security-group-ids" to create vm nics
	eniID, eni, err := n.manager.api.CreateNetworkInterface(ctx, subnet.ID, subnet.VirtualNetworkID, instanceID, []string{}, string(pool))
	if err != nil {
		return 0, unableToCreateENI, fmt.Errorf("%s %s", errUnableToCreateENI, err)
	}
	eni.Pool = pool.String()

	scopedLog = scopedLog.WithField(fieldENIID, eniID)

	if subnet.CIDR != nil {
		eni.Subnet.CIDR = subnet.CIDR.String()
	}

	// Add tag to nic before attaching it to VM to make sure that
	// the returned instance nics in func instancesAPI.Resync() has necessary tags
	index, err := n.allocENIIndex()
	if err != nil {
		scopedLog.WithField("instanceID", instanceID).Error(err)
		return 0, "Failed to allocate eni index", err
	}
	scopedLog.Debugf("########### got index is %d", index)
	eniIndex := utils.FillTagWithENIIndex(index)
	err = n.manager.api.AddTagToNetworkInterface(ctx, eniID, eniIndex)
	if err != nil {
		scopedLog.Errorf("########### Failed to add tag with error: %+v, %s", err, err)
		err = n.manager.api.DeleteNetworkInterface(ctx, eniID)
		if err != nil {
			scopedLog.Errorf("Failed to release ENI after failure to tag index, %s", err.Error())
		}
		return 0, unableToTagENI, fmt.Errorf("%s %s", unableToTagENI, err)
	}

	err = n.manager.api.AttachNetworkInterface(ctx, instanceID, eniID)
	if err != nil {
		scopedLog.Errorf("Failed to attach ENI: %s to instance: %s, with error: %s", eniID, instanceID, err.Error())
		if ifaces, err1 := n.manager.api.ListNetworkInterface(ctx, instanceID); err1 == nil {
			for _, iface := range ifaces {
				if iface.PortID == eniID {
					err2 := n.manager.api.DetachNetworkInterface(ctx, instanceID, eniID)
					if err2 != nil {
						scopedLog.Errorf("########### Failed to detach network interfaces, %s", err2.Error())
					}
					break
				}
			}
		} else {
			scopedLog.Infof("########### Failed to list network interfaces, %s", err1.Error())
		}

		err3 := n.manager.api.DeleteNetworkInterface(ctx, eniID)
		if err3 != nil {
			scopedLog.Errorf("Failed to release ENI after failure to attach, %s", err3.Error())
		}
		return 0, unableToAttachENI, fmt.Errorf("%s %s", errUnableToAttachENI, err)
	}
	eni.Tags = []string{eniIndex}
	n.enis[eniID] = *eni
	n.poolsEnis[pool] = append(n.poolsEnis[pool], eniID)
	scopedLog.Infof("Attached ENI to instance:%s with index:%d", instanceID, index)

	// Add the information of the created ENI to the instances manager
	n.manager.UpdateENI(instanceID, eni)
	return toAllocate, "", nil
}

// ResyncInterfacesAndIPs is called to retrieve and ENIs and IPs as known to
// the OpenStack API and return them
func (n *Node) ResyncInterfacesAndIPs(ctx context.Context, scopedLog *logrus.Entry) (
	available ipamTypes.AllocationMap,
	stats stats.InterfaceStats,
	err error) {
	limits, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return nil, stats, fmt.Errorf(errUnableToDetermineLimits)
	}

	stats.NodeCapacity = limits.IPv4 * limits.Adapters

	instanceID := n.node.InstanceID()
	available = ipamTypes.AllocationMap{}

	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.enis = map[string]eniTypes.ENI{}

	n.manager.ForeachInstance(instanceID,
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if !ok {
				return nil
			}

			n.enis[e.ID] = *e

			if pool := e.Pool; pool != "" {
				n.poolsEnis[ipam.Pool(pool)] = append(n.poolsEnis[ipam.Pool(pool)], e.ID)
			}

			if utils.IsExcludedByTags(e.Tags) {
				return nil
			}

			availableOnENI := math.IntMax(limits.IPv4-len(e.SecondaryIPSets), 0)
			if availableOnENI > 0 {
				stats.RemainingAvailableInterfaceCount++
			}

			for _, ip := range e.SecondaryIPSets {
				available[ip.IpAddress] = ipamTypes.AllocationIP{Resource: e.ID}
			}

			return nil
		})
	enis := len(n.enis)

	// An ECS instance has at least one ENI attached, no ENI found implies instance not found.
	if enis == 0 {
		scopedLog.Warning("Instance not found! Please delete corresponding ciliumnode if instance has already been deleted.")
		return nil, stats, fmt.Errorf("unable to retrieve ENIs")
	}

	stats.RemainingAvailableInterfaceCount += limits.Adapters - len(n.enis)

	scopedLog.Debugf("######### ResyncInterfacesAndIPs result, stats is %+v, available is %+v", stats, available)
	return available, stats, nil
}

// PrepareIPAllocation returns the number of ENI IPs and interfaces that can be
// allocated/created.
func (n *Node) PrepareIPAllocation(scopedLog *logrus.Entry, pool ipam.Pool) (*ipam.AllocationAction, error) {
	l, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return nil, fmt.Errorf(errUnableToDetermineLimits)
	}
	a := &ipam.AllocationAction{}

	n.mutex.RLock()
	defer n.mutex.RUnlock()

	for key, e := range n.enis {

		// enis that belong to the pool
		if pool != "" {
			if e.Pool != pool.String() {
				continue
			}
		}

		scopedLog.WithFields(logrus.Fields{
			fieldENIID:  e.ID,
			"ipv4Limit": l.IPv4,
			"allocated": len(e.SecondaryIPSets),
		}).Debug("Considering ENI for allocation")

		if utils.IsExcludedByTags(e.Tags) {
			continue
		}

		availableOnENI := math.IntMax(l.IPv4-len(e.SecondaryIPSets), 0)
		if availableOnENI <= 0 {
			continue
		} else {
			a.InterfaceCandidates++
		}

		scopedLog.WithFields(logrus.Fields{
			fieldENIID:       e.ID,
			"availableOnENI": availableOnENI,
		}).Debug("ENI has IPs available")

		if subnet := n.manager.GetSubnet(e.Subnet.ID); subnet != nil {
			if a.InterfaceID == "" {
				scopedLog.WithFields(logrus.Fields{
					"subnetID":           e.Subnet.ID,
					"availableAddresses": subnet.AvailableAddresses,
				}).Debug("Subnet has IPs available")

				a.InterfaceID = key
				a.PoolID = ipamTypes.PoolID(subnet.ID)
				a.AvailableForAllocation = math.IntMin(subnet.AvailableAddresses, availableOnENI)
			}
		}
	}
	a.EmptyInterfaceSlots = l.Adapters - len(n.enis)
	scopedLog.Debugf("############ Do prepare ip allocation, result is %+v", a)
	return a, nil
}

// AllocateIPs performs the ENI allocation operation
func (n *Node) AllocateIPs(ctx context.Context, a *ipam.AllocationAction, pool ipam.Pool) error {
	_, err := n.manager.api.AssignPrivateIPAddresses(ctx, a.InterfaceID, a.AvailableForAllocation, pool.String())
	return err
}

// PrepareIPRelease prepares the release of ENI IPs.
func (n *Node) PrepareIPRelease(excessIPs int, scopedLog *logrus.Entry, pool ipam.Pool) *ipam.ReleaseAction {
	r := &ipam.ReleaseAction{}

	n.mutex.Lock()
	defer n.mutex.Unlock()

	// Iterate over ENIs on this node, select the ENI with the most
	// addresses available for release
	for _, eid := range n.poolsEnis[pool] {
		var e eniTypes.ENI
		var ok bool
		if e, ok = n.enis[eid]; !ok {
			continue
		}
		scopedLog.WithFields(logrus.Fields{
			fieldENIID:     e.ID,
			"numAddresses": len(e.SecondaryIPSets),
		}).Debug("Considering ENI for IP release")

		if e.Type != eniTypes.ENITypePrimary {
			continue
		}

		if utils.IsExcludedByTags(e.Tags) {
			continue
		}

		// Count free IP addresses on this ENI
		ipsOnENI := n.k8sObj.Status.OpenStack.ENIs[e.ID].SecondaryIPSets
		freeIpsOnENI := []string{}
		for _, ip := range ipsOnENI {
			_, ipUsed := n.k8sObj.Status.IPAM.PoolUsed[pool.String()][ip.IpAddress]
			_, ipExcluded := n.manager.excludeIPs[ip.IpAddress]
			if !ipUsed && !ipExcluded {
				freeIpsOnENI = append(freeIpsOnENI, ip.IpAddress)
			}
		}
		freeOnENICount := len(freeIpsOnENI)

		if freeOnENICount <= 0 {
			continue
		}

		scopedLog.WithFields(logrus.Fields{
			fieldENIID:       e.ID,
			"excessIPs":      excessIPs,
			"freeOnENICount": freeOnENICount,
		}).Debugln("ENI has unused IPs that can be released")
		maxReleaseOnENI := math.IntMin(freeOnENICount, excessIPs)

		r.InterfaceID = eid
		r.PoolID = ipamTypes.PoolID(e.VPC.ID)
		r.IPsToRelease = freeIpsOnENI[:maxReleaseOnENI]
	}

	return r
}

// ReleaseIPs performs the ENI IP release operation
func (n *Node) ReleaseIPs(ctx context.Context, r *ipam.ReleaseAction, pool string) error {
	err := n.manager.api.UnassignPrivateIPAddresses(ctx, r.InterfaceID, r.IPsToRelease, pool)
	if err != nil {
		return err
	}
	return nil
}

// GetMaximumAllocatableIPv4 returns the maximum amount of IPv4 addresses
// that can be allocated to the instance
func (n *Node) GetMaximumAllocatableIPv4() int {
	n.mutex.RLock()
	defer n.mutex.RUnlock()

	// Retrieve l for the instance type
	l, limitsAvailable := n.getLimitsLocked()
	if !limitsAvailable {
		return 0
	}

	// Return the maximum amount of IP addresses allocatable on the instance
	// reserve Primary eni
	return (l.Adapters - 1) * l.IPv4
}

// GetMinimumAllocatableIPv4 returns the minimum amount of IPv4 addresses that
// must be allocated to the instance.
func (n *Node) GetMinimumAllocatableIPv4() int {
	return defaults.IPAMPreAllocation
}

func (n *Node) loggerLocked() *logrus.Entry {
	if n == nil || n.instanceID == "" {
		return log
	}

	return log.WithField("instanceID", n.instanceID)
}

func (n *Node) IsPrefixDelegated() bool {
	return false
}

func (n *Node) GetUsedIPWithPrefixes() int {
	if n.k8sObj == nil {
		return 0
	}
	return len(n.k8sObj.Status.IPAM.Used)
}

// GetPoolUsedIPWithPrefixes returns the ip used count used by specific pool
func (n *Node) GetPoolUsedIPWithPrefixes(pool string) int {
	if n.k8sObj == nil {
		return 0
	}
	if allocate, ok := n.k8sObj.Status.IPAM.PoolUsed[pool]; ok {
		return len(allocate)
	}
	return 0
}

// getLimits returns the interface and IP limits of this node
func (n *Node) getLimits() (ipamTypes.Limits, bool) {
	n.mutex.RLock()
	l, b := n.getLimitsLocked()
	n.mutex.RUnlock()
	return l, b
}

// getLimitsLocked is the same function as getLimits, but assumes the n.mutex
// is read locked.
func (n *Node) getLimitsLocked() (ipamTypes.Limits, bool) {
	return limits.Get(n.k8sObj.Spec.OpenStack.InstanceType)
}

func (n *Node) getSecurityGroupIDs(ctx context.Context, eniSpec eniTypes.Spec) ([]string, error) {
	// ENI must have at least one security group
	// 1. use security group defined by user
	// 2. use security group used by primary ENI (eth0)

	if len(eniSpec.SecurityGroups) > 0 {
		return eniSpec.SecurityGroups, nil
	}

	var securityGroups []string

	n.manager.ForeachInstance(n.node.InstanceID(),
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if ok && e.Type == eniTypes.ENITypePrimary {
				securityGroups = append(securityGroups, e.SecurityGroups...)
			}
			return nil
		})

	if len(securityGroups) <= 0 {
		return nil, fmt.Errorf("failed to get security group ids")
	}

	return securityGroups, nil
}

// findSuitableSubnet attempts to find a subnet to allocate an ENI in according to the following heuristic.
//  0. In general, the subnet has to be in the same VPC and match the availability zone of the
//     node. If there are multiple candidates, we choose the subnet with the most addresses
//     available.
//  1. If we have explicit ID or tag constraints, chose a matching subnet. ID constraints take
//     precedence.
//  2. If we have no explicit constraints, try to use the subnet the first ENI of the node was
//     created in, to avoid putting the ENI in a surprising subnet if possible.
//  3. If none of these work, fall back to just choosing the subnet with the most addresses
//     available.
func (n *Node) findSuitableSubnet(spec eniTypes.Spec, limits ipamTypes.Limits, subnetId string) *ipamTypes.Subnet {
	if subnetId != "" {
		return n.manager.GetSubnet(subnetId)
	}

	return nil
}

// allocENIIndex will alloc an monotonically increased index for each ENI on this instance.
// The index generated the first time this ENI is created, and stored in ENI.Tags.
func (n *Node) allocENIIndex() (int, error) {
	// alloc index for each created ENI
	used := make([]bool, maxENIPerNode)
	for _, v := range n.enis {
		index := utils.GetENIIndexFromTags(v.Tags)
		if index > maxENIPerNode || index < 0 {
			return 0, fmt.Errorf("ENI index(%d) is out of range", index)
		}
		used[index] = true
	}
	// ECS has at least 1 ENI, 0 is reserved for eth0
	i := 1
	for ; i < maxENIPerNode; i++ {
		if !used[i] {
			break
		}
	}
	return i, nil
}

// ResyncInterfacesAndIPsByPool is called to retrieve and ENIs and IPs by pool as known to
// the OpenStack API and return them
func (n *Node) ResyncInterfacesAndIPsByPool(ctx context.Context, scopedLog *logrus.Entry) (poolAvailable map[ipam.Pool]ipamTypes.AllocationMap, stats stats.InterfaceStats, err error) {
	limits, limitsAvailable := n.getLimits()
	if !limitsAvailable {
		return nil, stats, fmt.Errorf(errUnableToDetermineLimits)
	}

	// During preparation of IP allocations, the primary NIC is not considered
	// for allocation, so we don't need to consider it for capacity calculation.
	stats.NodeCapacity = limits.IPv4 * (limits.Adapters - 1)

	instanceID := n.node.InstanceID()
	poolAvailable = map[ipam.Pool]ipamTypes.AllocationMap{}
	n.mutex.Lock()
	defer n.mutex.Unlock()
	n.enis = map[string]eniTypes.ENI{}
	n.poolsEnis = map[ipam.Pool][]string{}

	n.manager.ForeachInstance(instanceID,
		func(instanceID, interfaceID string, rev ipamTypes.InterfaceRevision) error {
			e, ok := rev.Resource.(*eniTypes.ENI)
			if !ok {
				return nil
			}

			n.enis[e.ID] = *e

			n.poolsEnis[ipam.Pool(e.Pool)] = append(n.poolsEnis[ipam.Pool(e.Pool)], e.ID)

			if utils.IsExcludedByTags(e.Tags) {
				return nil
			}
			if _, ok := poolAvailable[ipam.Pool(e.Pool)]; !ok {
				poolAvailable[ipam.Pool(e.Pool)] = ipamTypes.AllocationMap{}
			}

			availableOnENI := math.IntMax(limits.IPv4-len(e.SecondaryIPSets), 0)
			if availableOnENI > 0 {
				stats.RemainingAvailableInterfaceCount++
			}

			for _, ip := range e.SecondaryIPSets {
				poolAvailable[ipam.Pool(e.Pool)][ip.IpAddress] = ipamTypes.AllocationIP{Resource: e.ID}
			}

			return nil
		})
	enis := len(n.enis)

	// An ECS instance has at least one ENI attached, no ENI found implies instance not found.
	if enis == 0 {
		scopedLog.Warning("Instance not found! Please delete corresponding ciliumnode if instance has already been deleted.")
		return nil, stats, fmt.Errorf("unable to retrieve ENIs")
	}

	stats.RemainingAvailableInterfaceCount += limits.Adapters - len(n.enis)

	scopedLog.Debugf("########### ResyncInterfacesAndIPs result, remainAvailableENIsCount is %d, poolAvailable is %+v", stats.RemainingAvailableInterfaceCount, poolAvailable)
	return poolAvailable, stats, nil
}

func (n *Node) AllocateStaticIP(ctx context.Context, address string, pool ipam.Pool, portId string) (string, string, error) {
	log.Infof("########## Do Allocate static IP..... %v", address)

	var interfaceId string
	enis := n.poolsEnis[pool]
	for _, eni := range enis {
		if _, exist := n.enis[eni]; exist {
			interfaceId = eni
			break
		}
	}

	if interfaceId == "" {
		return "", "", errors.New("no interface available")
	}

	portId, err := n.manager.api.AssignStaticPrivateIPAddresses(ctx, interfaceId, address, portId)
	if err != nil {
		return "", "", err
	}

	return portId, interfaceId, nil
}

func (n *Node) UnbindStaticIP(ctx context.Context, address string, vpcID string) error {
	n.mutex.Lock()
	defer n.mutex.Unlock()
	err := n.manager.api.UnassignPrivateIPAddressesRetainPort(ctx, vpcID, address)
	if err != nil {
		return err
	}

	return nil
}

func (n *Node) ReleaseStaticIP(address string, pool string, portId string) error {
	if enis, ok := n.poolsEnis[ipam.Pool(pool)]; ok && len(enis) > 0 {
		if _, ok = n.k8sObj.Status.OpenStack.ENIs[enis[0]]; !ok {
			return fmt.Errorf("eni %s not found on node %s", enis[0], n.k8sObj.Name)
		}
		err := n.manager.api.DeleteNeutronPort(address, n.k8sObj.Status.OpenStack.ENIs[enis[0]].VPC.ID, portId, pool)
		if err != nil {
			log.Errorf("release static failed: %v", err)
			return err
		}
	} else {
		return fmt.Errorf("no eni found in pool: %s", pool)
	}
	return nil
}
