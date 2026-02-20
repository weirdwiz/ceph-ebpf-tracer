package correlator

import (
	"context"
	"testing"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestLookupAfterSync(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{
					CSI: &corev1.CSIPersistentVolumeSource{
						Driver:           "openshift-storage.rbd.csi.ceph.com",
						VolumeAttributes: map[string]string{"imageName": "csi-vol-abc", "pool": "ocs-pool"},
					},
				},
				ClaimRef: &corev1.ObjectReference{
					Name:      "my-pvc",
					Namespace: "default",
				},
			},
		},
		&corev1.PersistentVolume{
			ObjectMeta: metav1.ObjectMeta{Name: "pv-nfs"},
			Spec: corev1.PersistentVolumeSpec{
				PersistentVolumeSource: corev1.PersistentVolumeSource{
					NFS: &corev1.NFSVolumeSource{Server: "nfs.local", Path: "/data"},
				},
			},
		},
	)

	c := New(client)
	ctx := context.Background()
	if err := c.syncAll(ctx); err != nil {
		t.Fatalf("syncAll: %v", err)
	}

	pvc := c.Lookup("csi-vol-abc")
	if pvc == nil {
		t.Fatal("Lookup(csi-vol-abc) returned nil")
	}
	if pvc.PVCName != "my-pvc" {
		t.Errorf("PVCName = %q, want %q", pvc.PVCName, "my-pvc")
	}
	if pvc.PVCNamespace != "default" {
		t.Errorf("PVCNamespace = %q, want %q", pvc.PVCNamespace, "default")
	}
	if pvc.Pool != "ocs-pool" {
		t.Errorf("Pool = %q, want %q", pvc.Pool, "ocs-pool")
	}

	// NFS PV should not be indexed
	if c.Lookup("nfs-anything") != nil {
		t.Error("NFS PV should not be indexed")
	}
}

func TestLookupMiss(t *testing.T) {
	c := New(fake.NewSimpleClientset())
	if pvc := c.Lookup("nonexistent"); pvc != nil {
		t.Errorf("Lookup(nonexistent) = %v, want nil", pvc)
	}
}

func TestProcessPVWithoutClaimRef(t *testing.T) {
	c := New(fake.NewSimpleClientset())
	c.mu.Lock()
	c.processPV(&corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-unbound"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "openshift-storage.rbd.csi.ceph.com",
					VolumeAttributes: map[string]string{"imageName": "csi-vol-unbound", "pool": "p"},
				},
			},
		},
	})
	c.mu.Unlock()

	pvc := c.Lookup("csi-vol-unbound")
	if pvc == nil {
		t.Fatal("expected entry for unbound PV")
	}
	if pvc.PVCName != "" {
		t.Errorf("PVCName = %q, want empty for unbound PV", pvc.PVCName)
	}
}

func TestRemovePV(t *testing.T) {
	c := New(fake.NewSimpleClientset())
	pv := &corev1.PersistentVolume{
		ObjectMeta: metav1.ObjectMeta{Name: "pv-1"},
		Spec: corev1.PersistentVolumeSpec{
			PersistentVolumeSource: corev1.PersistentVolumeSource{
				CSI: &corev1.CSIPersistentVolumeSource{
					Driver:           "openshift-storage.rbd.csi.ceph.com",
					VolumeAttributes: map[string]string{"imageName": "csi-vol-rm", "pool": "p"},
				},
			},
		},
	}

	c.mu.Lock()
	c.processPV(pv)
	c.mu.Unlock()

	if c.Lookup("csi-vol-rm") == nil {
		t.Fatal("expected entry after processPV")
	}

	c.mu.Lock()
	c.removePV(pv)
	c.mu.Unlock()

	if c.Lookup("csi-vol-rm") != nil {
		t.Error("expected nil after removePV")
	}
}
