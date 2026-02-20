package correlator

import (
	"context"
	"strings"
	"sync"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
)

// PVCInfo holds the PVC identity for an RBD image.
type PVCInfo struct {
	PVCName      string
	PVCNamespace string
	PVName       string
	ImageName    string
	Pool         string
}

// Correlator maps RBD image names to PVC identities by watching PV objects.
type Correlator struct {
	mu      sync.RWMutex
	byImage map[string]*PVCInfo // keyed by imageName (e.g., "csi-vol-xxx")
	client  kubernetes.Interface
	stopCh  chan struct{}
}

func New(client kubernetes.Interface) *Correlator {
	return &Correlator{
		byImage: make(map[string]*PVCInfo),
		client:  client,
		stopCh:  make(chan struct{}),
	}
}

// Run performs an initial PV sync, then starts a background goroutine
// that watches PersistentVolumes and keeps the image->PVC map up to date.
// The background goroutine stops when ctx is cancelled.
func (c *Correlator) Run(ctx context.Context) {
	// Initial list
	if err := c.syncAll(ctx); err != nil {
		klog.Errorf("initial PV sync failed: %v", err)
	}

	go c.watchLoop(ctx)
}

func (c *Correlator) syncAll(ctx context.Context) error {
	pvList, err := c.client.CoreV1().PersistentVolumes().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range pvList.Items {
		c.processPV(&pvList.Items[i])
	}

	klog.Infof("correlator synced %d RBD PVs", len(c.byImage))
	return nil
}

func (c *Correlator) watchLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		watcher, err := c.client.CoreV1().PersistentVolumes().Watch(ctx, metav1.ListOptions{})
		if err != nil {
			klog.Errorf("PV watch failed: %v, retrying in 5s", err)
			time.Sleep(5 * time.Second)
			continue
		}

		c.handleWatch(ctx, watcher)
	}
}

func (c *Correlator) handleWatch(ctx context.Context, watcher watch.Interface) {
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.ResultChan():
			if !ok {
				klog.V(2).Info("PV watch channel closed, will reconnect")
				return
			}

			pv, ok := event.Object.(*corev1.PersistentVolume)
			if !ok {
				continue
			}

			c.mu.Lock()
			switch event.Type {
			case watch.Added, watch.Modified:
				c.processPV(pv)
			case watch.Deleted:
				c.removePV(pv)
			}
			c.mu.Unlock()
		}
	}
}

// processPV extracts RBD image info from a PV and stores the PVC mapping.
// Must be called with c.mu held.
func (c *Correlator) processPV(pv *corev1.PersistentVolume) {
	if pv.Spec.CSI == nil {
		return
	}

	if !strings.HasSuffix(pv.Spec.CSI.Driver, "rbd.csi.ceph.com") {
		return
	}

	imageName := pv.Spec.CSI.VolumeAttributes["imageName"]
	if imageName == "" {
		return
	}

	info := &PVCInfo{
		PVName:    pv.Name,
		ImageName: imageName,
		Pool:      pv.Spec.CSI.VolumeAttributes["pool"],
	}

	if pv.Spec.ClaimRef != nil {
		info.PVCName = pv.Spec.ClaimRef.Name
		info.PVCNamespace = pv.Spec.ClaimRef.Namespace
	}

	c.byImage[imageName] = info
}

// removePV removes a PV's image mapping. Must be called with c.mu held.
func (c *Correlator) removePV(pv *corev1.PersistentVolume) {
	if pv.Spec.CSI == nil {
		return
	}
	imageName := pv.Spec.CSI.VolumeAttributes["imageName"]
	delete(c.byImage, imageName)
}

// Lookup returns PVC info for an RBD image name, or nil if unknown.
func (c *Correlator) Lookup(imageName string) *PVCInfo {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.byImage[imageName]
}
