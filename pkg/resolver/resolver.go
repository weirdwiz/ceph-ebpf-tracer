package resolver

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

// Rook labels that identify Ceph daemon pods.
var daemonLabels = map[string]string{
	"rook-ceph-osd": "osd",
	"rook-ceph-mon": "mon",
	"rook-ceph-mgr": "mgr",
	"rook-ceph-mds": "mds",
}

// podLabelSelector matches all Ceph daemon pod types.
const daemonLabelSelector = "app in (rook-ceph-osd,rook-ceph-mon,rook-ceph-mgr,rook-ceph-mds)"

// svcLabelSelector matches MON services (which have ClusterIPs clients connect to).
const svcLabelSelector = "app=rook-ceph-mon"

// DaemonInfo identifies a Ceph daemon or client pod by its role and ID.
type DaemonInfo struct {
	Role     string // "osd", "mon", "mgr", "mds", "client"
	DaemonID string // e.g. "osd-0", "mon-a", "mgr-a", "my-app"
}

// Resolver maps IP addresses to Ceph daemon or client pod identities
// by watching pods and services.
type Resolver struct {
	mu        sync.RWMutex
	byIP      map[string]*DaemonInfo
	client    kubernetes.Interface
	namespace string // Ceph namespace (for daemon pods + MON services)
	nodeName  string // local node name (for client pod resolution)
}

func New(client kubernetes.Interface, namespace, nodeName string) *Resolver {
	return &Resolver{
		byIP:      make(map[string]*DaemonInfo),
		client:    client,
		namespace: namespace,
		nodeName:  nodeName,
	}
}

// Run performs an initial sync, then starts background watchers for
// Ceph daemon pods, MON services, and local client pods.
// The watchers stop when ctx is cancelled.
func (r *Resolver) Run(ctx context.Context) {
	if err := r.syncAll(ctx); err != nil {
		klog.Errorf("initial daemon sync failed: %v", err)
	}

	go r.watchDaemonPodLoop(ctx)
	go r.watchSvcLoop(ctx)
	if r.nodeName != "" {
		go r.watchLocalPodLoop(ctx)
	}
}

// Lookup returns info for an IP, or nil if the IP is unknown.
func (r *Resolver) Lookup(ip string) *DaemonInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byIP[ip]
}

func (r *Resolver) syncAll(ctx context.Context) error {
	// Sync Ceph daemon pods
	pods, err := r.client.CoreV1().Pods(r.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: daemonLabelSelector,
	})
	if err != nil {
		return err
	}

	// Sync MON services
	svcs, err := r.client.CoreV1().Services(r.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: svcLabelSelector,
	})
	if err != nil {
		return err
	}

	r.mu.Lock()

	for i := range pods.Items {
		r.processDaemonPod(&pods.Items[i])
	}
	for i := range svcs.Items {
		r.processSvc(&svcs.Items[i])
	}

	daemonCount := len(r.byIP)
	r.mu.Unlock()

	// Sync all pods on the local node (includes non-Ceph pods)
	clientCount := 0
	if r.nodeName != "" {
		localPods, err := r.client.CoreV1().Pods("").List(ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + r.nodeName,
		})
		if err != nil {
			klog.Warningf("listing local pods: %v", err)
		} else {
			r.mu.Lock()
			for i := range localPods.Items {
				pod := &localPods.Items[i]
				// Field selector may not filter in all clients (e.g., fake).
				if pod.Spec.NodeName != r.nodeName {
					continue
				}
				if r.processLocalPod(pod) {
					clientCount++
				}
			}
			r.mu.Unlock()
		}
	}

	klog.Infof("resolver synced %d daemon IPs + %d client pod IPs", daemonCount, clientCount)
	return nil
}

// processDaemonPod indexes a Ceph daemon pod by its IP.
// Must be called with r.mu held.
func (r *Resolver) processDaemonPod(pod *corev1.Pod) {
	app := pod.Labels["app"]
	role, ok := daemonLabels[app]
	if !ok {
		return
	}

	ip := pod.Status.PodIP
	if ip == "" {
		return
	}

	daemonID := parseDaemonID(role, pod.Name)
	r.byIP[ip] = &DaemonInfo{Role: role, DaemonID: daemonID}
}

// processLocalPod indexes a non-daemon pod on the local node as a "client".
// Returns true if the pod was added (i.e., it wasn't already a daemon).
// Must be called with r.mu held.
func (r *Resolver) processLocalPod(pod *corev1.Pod) bool {
	ip := pod.Status.PodIP
	if ip == "" {
		return false
	}

	// Don't overwrite daemon entries -- they have more specific roles.
	if existing, ok := r.byIP[ip]; ok && existing.Role != "client" {
		return false
	}

	// Skip host-network pods (their IP is the node IP, not a pod IP).
	if pod.Spec.HostNetwork {
		return false
	}

	id := clientID(pod)
	r.byIP[ip] = &DaemonInfo{Role: "client", DaemonID: id}
	return true
}

// removeLocalPod removes a client pod's IP mapping.
// Only removes if the current entry is a "client" (don't remove daemon entries).
// Must be called with r.mu held.
func (r *Resolver) removeLocalPod(pod *corev1.Pod) {
	ip := pod.Status.PodIP
	if ip == "" {
		return
	}
	if existing, ok := r.byIP[ip]; ok && existing.Role == "client" {
		delete(r.byIP, ip)
	}
}

// removeDaemonPod removes a daemon pod's IP mapping.
// Must be called with r.mu held.
func (r *Resolver) removeDaemonPod(pod *corev1.Pod) {
	ip := pod.Status.PodIP
	if ip != "" {
		delete(r.byIP, ip)
	}
}

// processSvc maps a MON service ClusterIP to a "mon" role.
// Must be called with r.mu held.
func (r *Resolver) processSvc(svc *corev1.Service) {
	if svc.Spec.ClusterIP == "" || svc.Spec.ClusterIP == "None" {
		return
	}

	daemonID := parseDaemonID("mon", svc.Name)
	r.byIP[svc.Spec.ClusterIP] = &DaemonInfo{Role: "mon", DaemonID: daemonID}
}

// removeSvc removes a service's ClusterIP mapping. Must be called with r.mu held.
func (r *Resolver) removeSvc(svc *corev1.Service) {
	if svc.Spec.ClusterIP != "" && svc.Spec.ClusterIP != "None" {
		delete(r.byIP, svc.Spec.ClusterIP)
	}
}

// clientID picks a short, stable identifier for a non-daemon pod.
// Prefers the "app" or "app.kubernetes.io/name" label, falls back to pod name.
func clientID(pod *corev1.Pod) string {
	if app := pod.Labels["app"]; app != "" {
		return app
	}
	if app := pod.Labels["app.kubernetes.io/name"]; app != "" {
		return app
	}
	return pod.Name
}

// parseDaemonID extracts a short daemon identifier from a pod/service name.
// "rook-ceph-osd-0-7978ddb84-m8ppl" -> "osd-0"
// "rook-ceph-mon-a-86bc697d4d-lbwqf" -> "mon-a"
// "rook-ceph-mon-a" (service) -> "mon-a"
func parseDaemonID(role, name string) string {
	prefix := "rook-ceph-" + role + "-"
	if !strings.HasPrefix(name, prefix) {
		return role
	}
	rest := name[len(prefix):]

	// For pods: "0-7978ddb84-m8ppl" or "a-86bc697d4d-lbwqf"
	// For services: "a"
	// Take only the first segment (before the first '-' that leads to a hash).
	parts := strings.SplitN(rest, "-", 2)
	return role + "-" + parts[0]
}

func (r *Resolver) watchDaemonPodLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		watcher, err := r.client.CoreV1().Pods(r.namespace).Watch(ctx, metav1.ListOptions{
			LabelSelector: daemonLabelSelector,
		})
		if err != nil {
			klog.Errorf("daemon pod watch failed: %v, retrying in 5s", err)
			time.Sleep(5 * time.Second)
			continue
		}

		r.handleDaemonPodWatch(ctx, watcher)
	}
}

func (r *Resolver) handleDaemonPodWatch(ctx context.Context, watcher watch.Interface) {
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.ResultChan():
			if !ok {
				klog.V(2).Info("daemon pod watch channel closed, will reconnect")
				return
			}

			pod, ok := event.Object.(*corev1.Pod)
			if !ok {
				continue
			}

			r.mu.Lock()
			switch event.Type {
			case watch.Added, watch.Modified:
				r.processDaemonPod(pod)
			case watch.Deleted:
				r.removeDaemonPod(pod)
			}
			r.mu.Unlock()
		}
	}
}

// watchLocalPodLoop watches all pods on the local node for client resolution.
func (r *Resolver) watchLocalPodLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		watcher, err := r.client.CoreV1().Pods("").Watch(ctx, metav1.ListOptions{
			FieldSelector: "spec.nodeName=" + r.nodeName,
		})
		if err != nil {
			klog.Errorf("local pod watch failed: %v, retrying in 5s", err)
			time.Sleep(5 * time.Second)
			continue
		}

		r.handleLocalPodWatch(ctx, watcher)
	}
}

func (r *Resolver) handleLocalPodWatch(ctx context.Context, watcher watch.Interface) {
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.ResultChan():
			if !ok {
				klog.V(2).Info("local pod watch channel closed, will reconnect")
				return
			}

			pod, ok := event.Object.(*corev1.Pod)
			if !ok {
				continue
			}

			if pod.Spec.NodeName != r.nodeName {
				continue
			}
			r.mu.Lock()
			switch event.Type {
			case watch.Added, watch.Modified:
				r.processLocalPod(pod)
			case watch.Deleted:
				r.removeLocalPod(pod)
			}
			r.mu.Unlock()
		}
	}
}

func (r *Resolver) watchSvcLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		watcher, err := r.client.CoreV1().Services(r.namespace).Watch(ctx, metav1.ListOptions{
			LabelSelector: svcLabelSelector,
		})
		if err != nil {
			klog.Errorf("MON service watch failed: %v, retrying in 5s", err)
			time.Sleep(5 * time.Second)
			continue
		}

		r.handleSvcWatch(ctx, watcher)
	}
}

func (r *Resolver) handleSvcWatch(ctx context.Context, watcher watch.Interface) {
	defer watcher.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case event, ok := <-watcher.ResultChan():
			if !ok {
				klog.V(2).Info("MON service watch channel closed, will reconnect")
				return
			}

			svc, ok := event.Object.(*corev1.Service)
			if !ok {
				continue
			}

			r.mu.Lock()
			switch event.Type {
			case watch.Added, watch.Modified:
				r.processSvc(svc)
			case watch.Deleted:
				r.removeSvc(svc)
			}
			r.mu.Unlock()
		}
	}
}
