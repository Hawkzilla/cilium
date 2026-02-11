package deviceplugin

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path"
	"sync"
	"time"

	"github.com/cilium/cilium/pkg/k8s/constants"
	"github.com/fsnotify/fsnotify"
	log "github.com/sirupsen/logrus"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	"google.golang.org/grpc/health/grpc_health_v1"
	v2 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	pluginapi "k8s.io/kubelet/pkg/apis/deviceplugin/v1beta1"
)

const (
	period              = 30 * time.Second
	ENIIPResourcePrefix = "openstack/eniip-"
)

var (
	KubeletSocket = pluginapi.DevicePluginPath + "kubelet.sock"
)

// Resource represents the shared state between the informer and device plugin
type Resource struct {
	IPCount int
	mutex   sync.Mutex

	UpdateSignal chan struct{}
	LabelCh      chan string
}

func (res *Resource) GetIPCount() int {
	res.mutex.Lock()
	defer res.mutex.Unlock()

	if res.IPCount < 0 {
		return 0
	}
	return res.IPCount
}

func (res *Resource) SetIPCount(count int) {
	res.mutex.Lock()
	defer res.mutex.Unlock()
	res.IPCount = count
}

// ENIIPDevicePlugin implements the Kubelet device plugin API
type ENIIPDevicePlugin struct {
	project     string
	server      *grpc.Server
	res         *Resource
	ctx         context.Context
	cancel      context.CancelFunc
	streamErrCh chan struct{}
	mutex       sync.Mutex
	client      *ClientSet
}

// NewENIIPDevicePlugin creates a new device plugin instance
func NewENIIPDevicePlugin(client *ClientSet, res *Resource) *ENIIPDevicePlugin {
	return &ENIIPDevicePlugin{
		res:         res,
		streamErrCh: make(chan struct{}, 1),
		client:      client,
	}
}

// Serve starts the device plugin and watches for Kubelet events
func (p *ENIIPDevicePlugin) Serve(ctx context.Context) error {

	if err := p.restart(); err != nil {
		return err
	}

	go p.dpHealthChecker(ctx)
	return p.watchKubeletLoop(ctx)
}

// getEndpoint returns the socket path for the current project
func (p *ENIIPDevicePlugin) getEndpoint() string {
	return path.Join(pluginapi.DevicePluginPath, fmt.Sprintf("eni-ip.sock"))
}

// startAndRegister starts the gRPC server and registers it with Kubelet
func (p *ENIIPDevicePlugin) startAndRegister() error {
	if err := p.start(); err != nil {
		return fmt.Errorf("device plugin start failed: %w", err)
	}

	if p.project == "" {
		return nil
	}

	retryCount := 5
	// Retry registration in case Kubelet is not ready yet (e.g., during restart)
	for i := 0; i < retryCount; i++ {
		if err := p.register(); err == nil {
			log.Infof("Registered device plugin for %s with Kubelet", p.project)
			return nil
		}
		log.Warnf("Device plugin register attempt %d/5 failed, retrying...", i+1)
		time.Sleep(1 * time.Second)
	}
	return fmt.Errorf("device plugin register failed after max retries")
}

// start launches the gRPC server
func (p *ENIIPDevicePlugin) start() error {
	ep := p.getEndpoint()

	// Remove any previous socket file
	if err := os.Remove(ep); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}

	sock, err := net.Listen("unix", ep)
	if err != nil {
		return err
	}

	p.server = grpc.NewServer()

	healthServer := health.NewServer()
	grpc_health_v1.RegisterHealthServer(p.server, healthServer)
	healthServer.SetServingStatus("", grpc_health_v1.HealthCheckResponse_SERVING)

	pluginapi.RegisterDevicePluginServer(p.server, p)

	go func() {
		if err := p.server.Serve(sock); err != nil {
			log.Errorf("Device plugin gRPC server error: %v", err)
		}
	}()

	// Dial once to ensure server is up
	conn, err := dialUnix(ep)
	if err != nil {
		return err
	}
	return conn.Close()
}

// restart stops the old server, cleans old state, and re-registers
func (p *ENIIPDevicePlugin) restart() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.server != nil {
		p.server.Stop()
		p.server = nil
	}
	if p.cancel != nil {
		p.cancel()
	}

	p.ctx, p.cancel = context.WithCancel(context.Background())
	return p.startAndRegister()
}

// watchKubeletLoop monitors kubelet.sock and project label changes
func (p *ENIIPDevicePlugin) watchKubeletLoop(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create watcher failed: %w", err)
	}
	defer watcher.Close()

	if err := watcher.Add(path.Clean(pluginapi.DevicePluginPath)); err != nil {
		return fmt.Errorf("watch kubelet failed: %w", err)
	}

	for {
		select {
		case <-ctx.Done():
			log.Infof("Watch loop stopped due to context cancel")
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				continue
			}
			switch {
			case event.Name == KubeletSocket && event.Has(fsnotify.Create):
				log.Infof("%s created, restarting.", pluginapi.KubeletSocket)
				if p.project == "" {
					log.Infof("No project found, skipping device plugin start")
					continue
				}
				if err := p.restart(); err != nil {
					log.Fatal("Failed to restart device plugin: ", err)
				}

			case event.Name == KubeletSocket && event.Op&fsnotify.Remove == fsnotify.Remove:
				log.Infof("Kubelet stopped")
			}

		case err := <-watcher.Errors:
			if err != nil {
				log.Fatal("Watch kubelet failed: ", err)
			}

		case newProject := <-p.res.LabelCh:
			if newProject == p.project {
				log.Infof("Project label unchanged, still %s", p.project)
				continue
			}
			oldProject := p.project
			p.project = newProject
			if err := p.restart(); err == nil {
				log.Infof("Project label changed (%s -> %s), restarted device plugin",
					oldProject, newProject)
			} else {
				log.Fatal("Failed to restart device plugin: ", err)
			}

		case <-p.streamErrCh:
			if err := p.restart(); err == nil {
				log.Infof("Stream error occurred, restarted device plugin for project %s", p.project)
			} else {
				log.Fatal("Failed to restart device plugin: ", err)
			}
		}
	}
}

// dialUnix connects to a Unix socket
func dialUnix(ep string) (*grpc.ClientConn, error) {
	tmpCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return grpc.DialContext(tmpCtx, ep,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithBlock(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return net.DialTimeout("unix", ep, 10*time.Second)
		}),
	)
}

// register registers device plugin to kubelet
func (p *ENIIPDevicePlugin) register() error {
	conn, err := dialUnix(KubeletSocket)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pluginapi.NewRegistrationClient(conn)

	tmpCtx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFunc()
	_, err = client.Register(tmpCtx, &pluginapi.RegisterRequest{
		Version:      pluginapi.Version,
		Endpoint:     path.Base(p.getEndpoint()),
		ResourceName: ENIIPResourcePrefix + p.project,
	})
	return err
}

// GetDevicePluginOptions returns options
func (p *ENIIPDevicePlugin) GetDevicePluginOptions(context.Context, *pluginapi.Empty) (*pluginapi.DevicePluginOptions, error) {
	return &pluginapi.DevicePluginOptions{}, nil
}

// ListAndWatch returns devices to kubelet
func (p *ENIIPDevicePlugin) ListAndWatch(_ *pluginapi.Empty, stream pluginapi.DevicePlugin_ListAndWatchServer) error {
	send := func(count int) error {
		devices := make([]*pluginapi.Device, count)
		for i := 0; i < count; i++ {
			devices[i] = &pluginapi.Device{
				ID:     fmt.Sprintf("%s%d", ENIIPResourcePrefix+p.project, i),
				Health: pluginapi.Healthy,
			}
		}
		resp := &pluginapi.ListAndWatchResponse{Devices: devices}
		if err := stream.Send(resp); err != nil {
			log.Errorf("Send devices error: %v", err)
			return err
		}
		log.Infof("Reported %d resources for %s", count, p.project)
		return nil
	}

	var genericSendFunc = func() (err error) {
		if err = send(p.res.GetIPCount()); err != nil {
			p.streamErrCh <- struct{}{}
		}
		return err
	}

	err := genericSendFunc() // send once at the beginning
	if err != nil {
		return err
	}

	ticker := time.NewTicker(period)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			err := genericSendFunc()
			if err != nil {
				return err
			}
		case <-p.res.UpdateSignal:
			log.Infof("Received update signal")
			err := genericSendFunc()
			if err != nil {
				return err
			}
		case <-p.ctx.Done(): // stop signal
			log.Infof("Server context canceled, stopping ListAndWatch")
			return nil
		case <-stream.Context().Done():
			log.Infof("Stream closed")
			return nil
		}
	}
}

// Allocate does nothing
func (p *ENIIPDevicePlugin) Allocate(_ context.Context, req *pluginapi.AllocateRequest) (*pluginapi.AllocateResponse, error) {
	resp := &pluginapi.AllocateResponse{}
	for range req.GetContainerRequests() {
		resp.ContainerResponses = append(resp.ContainerResponses, &pluginapi.ContainerAllocateResponse{})
	}
	return resp, nil
}

func (p *ENIIPDevicePlugin) PreStartContainer(context.Context, *pluginapi.PreStartContainerRequest) (*pluginapi.PreStartContainerResponse, error) {
	return &pluginapi.PreStartContainerResponse{}, nil
}

func (p *ENIIPDevicePlugin) GetPreferredAllocation(context.Context, *pluginapi.PreferredAllocationRequest) (*pluginapi.PreferredAllocationResponse, error) {
	return &pluginapi.PreferredAllocationResponse{}, nil
}

// dpHealthChecker periodically validates the device plugin state
func (p *ENIIPDevicePlugin) dpHealthChecker(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			log.Infof("Health checker stopped due to context cancel")
			return
		case <-ticker.C:
			if err := p.checkHealth(); err != nil {
				log.Fatalf("Device plugin health check failed: %v", err)
			}
		}
	}
}

// checkHealth ensures the device plugin is running and counts match allocatable
func (p *ENIIPDevicePlugin) checkHealth() error {
	if p.project == "" {
		log.Infof("No project set, skip health check")
		return nil
	}

	for i := 0; i < 10; i++ {
		// Check if gRPC server is up
		if conn, err := dialUnix(p.getEndpoint()); err == nil {
			conn.Close()
			nodeName := os.Getenv(constants.EnvNodeNameSpec)
			node, err := p.client.K8sClient.CoreV1().Nodes().Get(context.TODO(), nodeName, v1.GetOptions{})
			if err != nil {
				log.Errorf("Failed to get node during health check: %s", err)
			} else {
				listCount := p.res.GetIPCount()
				quantity := node.Status.Allocatable[v2.ResourceName(ENIIPResourcePrefix+p.project)]
				if int64(listCount) == quantity.Value() {
					log.Infof("Health check passed for project %s", p.project)
					return nil
				}
				log.Errorf("Mismatch in device count: expected=%d, allocatable=%d", listCount, quantity.Value())
			}
		} else {
			log.Errorf("Failed to dial device plugin server: %s", err)
		}
		time.Sleep(2 * time.Second)
	}
	return fmt.Errorf("device plugin health check failed for project %s", p.project)
}
