package resolver

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

const testNS = "openshift-storage"

func cephPod(name, app, ip string) *corev1.Pod {
	return &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNS,
			Labels:    map[string]string{"app": app},
		},
		Status: corev1.PodStatus{PodIP: ip},
	}
}

func monSvc(name, clusterIP string) *corev1.Service {
	return &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      name,
			Namespace: testNS,
			Labels:    map[string]string{"app": "rook-ceph-mon"},
		},
		Spec: corev1.ServiceSpec{ClusterIP: clusterIP},
	}
}

func TestSyncAllDaemonTypes(t *testing.T) {
	client := fake.NewSimpleClientset(
		cephPod("rook-ceph-osd-0-abc123-xyz", "rook-ceph-osd", "10.129.2.40"),
		cephPod("rook-ceph-osd-1-def456-uvw", "rook-ceph-osd", "10.128.2.55"),
		cephPod("rook-ceph-mon-a-ghi789-rst", "rook-ceph-mon", "10.131.0.19"),
		cephPod("rook-ceph-mgr-a-jkl012-opq", "rook-ceph-mgr", "10.129.2.25"),
		cephPod("rook-ceph-mds-ocs-storagecluster-cephfilesystem-a-mno345-lmn", "rook-ceph-mds", "10.131.0.29"),
		monSvc("rook-ceph-mon-a", "172.30.141.223"),
		monSvc("rook-ceph-mon-b", "172.30.188.30"),
	)

	r := New(client, testNS)
	if err := r.syncAll(context.Background()); err != nil {
		t.Fatalf("syncAll: %v", err)
	}

	tests := []struct {
		ip       string
		wantRole string
		wantID   string
	}{
		{"10.129.2.40", "osd", "osd-0"},
		{"10.128.2.55", "osd", "osd-1"},
		{"10.131.0.19", "mon", "mon-a"},
		{"10.129.2.25", "mgr", "mgr-a"},
		{"10.131.0.29", "mds", "mds-ocs"},
		{"172.30.141.223", "mon", "mon-a"},
		{"172.30.188.30", "mon", "mon-b"},
	}

	for _, tt := range tests {
		info := r.Lookup(tt.ip)
		if info == nil {
			t.Errorf("Lookup(%s) = nil, want role=%s", tt.ip, tt.wantRole)
			continue
		}
		if info.Role != tt.wantRole {
			t.Errorf("Lookup(%s).Role = %q, want %q", tt.ip, info.Role, tt.wantRole)
		}
		if info.DaemonID != tt.wantID {
			t.Errorf("Lookup(%s).DaemonID = %q, want %q", tt.ip, info.DaemonID, tt.wantID)
		}
	}
}

func TestLookupMiss(t *testing.T) {
	r := New(fake.NewSimpleClientset(), testNS)
	if info := r.Lookup("1.2.3.4"); info != nil {
		t.Errorf("Lookup(unknown) = %v, want nil", info)
	}
}

func TestRemovePod(t *testing.T) {
	pod := cephPod("rook-ceph-osd-0-abc-xyz", "rook-ceph-osd", "10.0.0.1")
	r := New(fake.NewSimpleClientset(pod), testNS)
	r.syncAll(context.Background())

	if r.Lookup("10.0.0.1") == nil {
		t.Fatal("expected entry after sync")
	}

	r.mu.Lock()
	r.removePod(pod)
	r.mu.Unlock()

	if r.Lookup("10.0.0.1") != nil {
		t.Error("expected nil after removePod")
	}
}

func TestRemoveSvc(t *testing.T) {
	svc := monSvc("rook-ceph-mon-a", "172.30.1.1")
	r := New(fake.NewSimpleClientset(svc), testNS)
	r.syncAll(context.Background())

	if r.Lookup("172.30.1.1") == nil {
		t.Fatal("expected entry after sync")
	}

	r.mu.Lock()
	r.removeSvc(svc)
	r.mu.Unlock()

	if r.Lookup("172.30.1.1") != nil {
		t.Error("expected nil after removeSvc")
	}
}

func TestHeadlessSvcSkipped(t *testing.T) {
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rook-ceph-mon-a",
			Namespace: testNS,
			Labels:    map[string]string{"app": "rook-ceph-mon"},
		},
		Spec: corev1.ServiceSpec{ClusterIP: "None"},
	}
	r := New(fake.NewSimpleClientset(svc), testNS)
	r.syncAll(context.Background())

	if len(r.byIP) != 0 {
		t.Errorf("headless service should not be indexed, got %d entries", len(r.byIP))
	}
}

func TestPodWithoutIP(t *testing.T) {
	pod := cephPod("rook-ceph-osd-0-abc-xyz", "rook-ceph-osd", "")
	r := New(fake.NewSimpleClientset(pod), testNS)
	r.syncAll(context.Background())

	if len(r.byIP) != 0 {
		t.Errorf("pod without IP should not be indexed, got %d entries", len(r.byIP))
	}
}

func TestParseDaemonID(t *testing.T) {
	tests := []struct {
		role, name string
		want       string
	}{
		{"osd", "rook-ceph-osd-0-7978ddb84-m8ppl", "osd-0"},
		{"osd", "rook-ceph-osd-12-abc123-xyz", "osd-12"},
		{"mon", "rook-ceph-mon-a-86bc697d4d-lbwqf", "mon-a"},
		{"mon", "rook-ceph-mon-a", "mon-a"},
		{"mgr", "rook-ceph-mgr-a-8798b476-tcbfz", "mgr-a"},
		{"mds", "rook-ceph-mds-ocs-storagecluster-a-abc-xyz", "mds-ocs"},
		{"osd", "weirdname", "osd"},
	}
	for _, tt := range tests {
		got := parseDaemonID(tt.role, tt.name)
		if got != tt.want {
			t.Errorf("parseDaemonID(%q, %q) = %q, want %q", tt.role, tt.name, got, tt.want)
		}
	}
}
