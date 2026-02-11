package deviceplugin

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	ipamOption "github.com/cilium/cilium/pkg/ipam/option"
	"github.com/cilium/cilium/pkg/k8s"
	cilium_v2 "github.com/cilium/cilium/pkg/k8s/apis/cilium.io/v2"
	"github.com/cilium/cilium/pkg/k8s/constants"
	"github.com/cilium/cilium/pkg/k8s/informer"
	slim_core_v1 "github.com/cilium/cilium/pkg/k8s/slim/k8s/api/core/v1"
	"github.com/cilium/cilium/pkg/k8s/utils"
	log "github.com/sirupsen/logrus"
	v12 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/tools/cache"
)

const LabelForProject = "node-role.kubernetes.io/project"

// PluginInformer watches CiliumNode and Pod resources on the local node,
// then updates resource information for the device plugin.
type PluginInformer struct {
	lock           sync.Mutex
	project        string
	ciliumNPClient *ClientSet
	podStore       cache.Store
	resource       *Resource
	ciliumNode     *cilium_v2.CiliumNode

	ciliumNodeInformer cache.Controller
	podInformer        cache.Controller
}

// NewPluginInformer creates a new informer instance for CiliumNode and Pod objects.
func NewPluginInformer(client *ClientSet, resource *Resource) *PluginInformer {
	p := &PluginInformer{resource: resource, ciliumNPClient: client}

	// Watch the local CiliumNode object by name
	_, p.ciliumNodeInformer = informer.NewInformer(
		utils.ListerWatcherWithFields(
			utils.ListerWatcherFromTyped[*cilium_v2.CiliumNodeList](client.CiliumClient.CiliumV2().CiliumNodes()),
			fields.OneTermEqualSelector("metadata.name", os.Getenv(constants.EnvNodeNameSpec)),
		),
		&cilium_v2.CiliumNode{},
		0,
		cache.ResourceEventHandlerFuncs{
			AddFunc: func(obj interface{}) {
				log.Infof("CiliumNode Add event")
				p.updateCiliumNode(obj)
			},
			UpdateFunc: func(_, newObj interface{}) {
				log.Infof("CiliumNode Update event")
				p.updateCiliumNode(newObj)
			},
		}, k8s.TransformToCiliumNode)

	// Watch Pods scheduled on the same node
	p.podStore, p.podInformer = informer.NewInformer(
		utils.ListerWatcherWithFields(
			utils.ListerWatcherFromTyped[*slim_core_v1.PodList](client.SlimClient.CoreV1().Pods(slim_core_v1.NamespaceAll)),
			fields.OneTermEqualSelector("spec.nodeName", os.Getenv(constants.EnvNodeNameSpec)),
		),
		&slim_core_v1.Pod{},
		0,
		cache.ResourceEventHandlerFuncs{},
		k8s.TransformToCiliumPod,
	)

	return p
}

// Run starts the informers and waits for caches to sync.
func (p *PluginInformer) Run(ctx context.Context) error {
	// Start pod informer in background
	go p.podInformer.Run(ctx.Done())

	if !cache.WaitForCacheSync(ctx.Done(), p.podInformer.HasSynced) {
		err := fmt.Errorf("timeout waiting for pod informer cache to sync")
		runtime.HandleError(err)
		return err
	}
	log.Infof("Pod informer initialized successfully")

	// CiliumNodeInformer depends on the pod cache store, so it must run after the pod cache is synced.
	// Run CiliumNode informer (blocking)
	p.ciliumNodeInformer.Run(ctx.Done())
	return nil
}

// updateCiliumNode processes changes to the local CiliumNode object.
func (p *PluginInformer) updateCiliumNode(obj interface{}) {
	ciliumNode := k8s.ObjToCiliumNode(obj)
	if ciliumNode == nil {
		return
	}

	p.lock.Lock()
	defer p.lock.Unlock()

	p.ciliumNode = ciliumNode

	// Update project label if changed
	if newProj := ciliumNode.Labels[LabelForProject]; newProj != "" {
		if newProj != p.project {
			p.project = newProj
			log.Infof("New project label detected: %s", newProj)
			p.resource.LabelCh <- newProj
		}
	}

	if p.project != "" {
		// Update available IP count
		latestCount := p.ListReportCount()
		if p.resource.IPCount != latestCount {
			p.resource.SetIPCount(latestCount)

			select {
			case <-time.After(time.Second * 10):
				log.Fatalf("Time out to update ip count")
			case p.resource.UpdateSignal <- struct{}{}:
				return
			}
		}
	}
}

// calculateIPCount counts available ENI secondary IPs (excluding those in handshake).
func (p *PluginInformer) calculateIPCount() int {
	if p.ciliumNode == nil {
		return 0
	}

	availableCount := 0
	for _, eni := range p.ciliumNode.Status.OpenStack.ENIs {
		if eni.Pool != "default" {
			for _, ipset := range eni.SecondaryIPSets {
				if ipStatus, inHandshake := p.ciliumNode.Status.IPAM.ReleaseIPs[ipset.IpAddress]; !inHandshake ||
					ipStatus == ipamOption.IPAMDoNotRelease {
					availableCount++
				}
			}
		}
	}
	return availableCount
}

// ListReportCount calculates available IPs minus pods without device plugin resources.
func (p *PluginInformer) ListReportCount() int {
	count, err := p.getNonDevicePluginPodCount(p.project)
	if err != nil {
		log.Infof("Failed to get non-deviceplugin pod count: %s", err)
		return -1
	}
	return p.calculateIPCount() - count
}

// getNonDevicePluginPodCount returns number of pods that do not use device plugin resources
// but still consume IPs outside the default pool.
func (p *PluginInformer) getNonDevicePluginPodCount(project string) (int, error) {
	count := 0
	values := p.podStore.List()

	// Get default pool CIDR
	defaultPool, err := p.ciliumNPClient.CiliumClient.CiliumV2alpha1().CiliumPodIPPools().
		Get(context.TODO(), "default", metav1.GetOptions{ResourceVersion: "0"})
	if err != nil {
		return 0, fmt.Errorf("unable to get default CiliumPodIPPool: %s", err)
	}

	_, ipNet, err := net.ParseCIDR(defaultPool.Spec.CIDR)
	if err != nil {
		return 0, fmt.Errorf("unable to parse default pool CIDR: %s", err)
	}

	for _, val := range values {
		pod, ok := val.(*slim_core_v1.Pod)
		if !ok {
			continue
		}

		if !pod.Spec.HostNetwork && len(pod.Spec.Containers) > 0 {
			// Pod without device plugin resource request, with IP not in default pool
			if _, exist := pod.Spec.Containers[0].Resources.Requests[v12.ResourceName(ENIIPResourcePrefix+project)]; !exist &&
				len(pod.Status.PodIPs) > 0 &&
				!ipNet.Contains(net.ParseIP(pod.Status.PodIP)) {
				count++
			}
		}
	}
	return count, nil
}
