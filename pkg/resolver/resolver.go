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
const podLabelSelector = "app in (rook-ceph-osd,rook-ceph-mon,rook-ceph-mgr,rook-ceph-mds)"

// svcLabelSelector matches MON services (which have ClusterIPs clients connect to).
const svcLabelSelector = "app=rook-ceph-mon"

// DaemonInfo identifies a Ceph daemon by its role and ID.
type DaemonInfo struct {
	Role     string // "osd", "mon", "mgr", "mds"
	DaemonID string // e.g. "osd-0", "mon-a", "mgr-a"
}

// Resolver maps IP addresses to Ceph daemon identities by watching
// pods and services in the Ceph namespace.
type Resolver struct {
	mu        sync.RWMutex
	byIP      map[string]*DaemonInfo
	client    kubernetes.Interface
	namespace string
}

func New(client kubernetes.Interface, namespace string) *Resolver {
	return &Resolver{
		byIP:      make(map[string]*DaemonInfo),
		client:    client,
		namespace: namespace,
	}
}

// Run performs an initial sync, then starts background watchers for
// pods and services. The watchers stop when ctx is cancelled.
func (r *Resolver) Run(ctx context.Context) {
	if err := r.syncAll(ctx); err != nil {
		klog.Errorf("initial daemon sync failed: %v", err)
	}

	go r.watchPodLoop(ctx)
	go r.watchSvcLoop(ctx)
}

// Lookup returns daemon info for an IP, or nil if the IP doesn't
// belong to a known Ceph daemon.
func (r *Resolver) Lookup(ip string) *DaemonInfo {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byIP[ip]
}

func (r *Resolver) syncAll(ctx context.Context) error {
	pods, err := r.client.CoreV1().Pods(r.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: podLabelSelector,
	})
	if err != nil {
		return err
	}

	svcs, err := r.client.CoreV1().Services(r.namespace).List(ctx, metav1.ListOptions{
		LabelSelector: svcLabelSelector,
	})
	if err != nil {
		return err
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	for i := range pods.Items {
		r.processPod(&pods.Items[i])
	}
	for i := range svcs.Items {
		r.processSvc(&svcs.Items[i])
	}

	klog.Infof("resolver synced %d Ceph daemon IPs", len(r.byIP))
	return nil
}

// processPod extracts the daemon role and IP from a Ceph daemon pod.
// Must be called with r.mu held.
func (r *Resolver) processPod(pod *corev1.Pod) {
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

// removePod removes a pod's IP mapping. Must be called with r.mu held.
func (r *Resolver) removePod(pod *corev1.Pod) {
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

func (r *Resolver) watchPodLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		watcher, err := r.client.CoreV1().Pods(r.namespace).Watch(ctx, metav1.ListOptions{
			LabelSelector: podLabelSelector,
		})
		if err != nil {
			klog.Errorf("daemon pod watch failed: %v, retrying in 5s", err)
			time.Sleep(5 * time.Second)
			continue
		}

		r.handlePodWatch(ctx, watcher)
	}
}

func (r *Resolver) handlePodWatch(ctx context.Context, watcher watch.Interface) {
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
				r.processPod(pod)
			case watch.Deleted:
				r.removePod(pod)
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
