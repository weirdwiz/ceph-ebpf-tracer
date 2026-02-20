package device

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMkdev(t *testing.T) {
	tests := []struct {
		major, minor uint32
		want         uint32
	}{
		{252, 0, 252 << 20},
		{252, 1, (252 << 20) | 1},
		{0, 0, 0},
		{8, 16, (8 << 20) | 16},
	}
	for _, tt := range tests {
		got := mkdev(tt.major, tt.minor)
		if got != tt.want {
			t.Errorf("mkdev(%d, %d) = %d, want %d", tt.major, tt.minor, got, tt.want)
		}
	}
}

func TestScan(t *testing.T) {
	// Create a fake sysfs tree
	dir := t.TempDir()

	// Create device "0"
	dev0 := filepath.Join(dir, "0")
	os.MkdirAll(dev0, 0o755)
	os.WriteFile(filepath.Join(dev0, "pool"), []byte("ocs-storagecluster\n"), 0o644)
	os.WriteFile(filepath.Join(dev0, "name"), []byte("csi-vol-abc\n"), 0o644)
	os.WriteFile(filepath.Join(dev0, "major"), []byte("252\n"), 0o644)
	os.WriteFile(filepath.Join(dev0, "minor"), []byte("0\n"), 0o644)
	os.WriteFile(filepath.Join(dev0, "pool_ns"), []byte("\n"), 0o644)

	// Create device "1"
	dev1 := filepath.Join(dir, "1")
	os.MkdirAll(dev1, 0o755)
	os.WriteFile(filepath.Join(dev1, "pool"), []byte("rbd-pool\n"), 0o644)
	os.WriteFile(filepath.Join(dev1, "name"), []byte("csi-vol-def\n"), 0o644)
	os.WriteFile(filepath.Join(dev1, "major"), []byte("252\n"), 0o644)
	os.WriteFile(filepath.Join(dev1, "minor"), []byte("1\n"), 0o644)

	// Non-numeric dir should be skipped
	os.MkdirAll(filepath.Join(dir, "add"), 0o755)

	w := &Watcher{
		devices: make(map[uint32]*RBDDevice),
		sysPath: dir,
	}

	if err := w.Scan(); err != nil {
		t.Fatalf("Scan() error: %v", err)
	}

	devices := w.GetDevices()
	if len(devices) != 2 {
		t.Fatalf("got %d devices, want 2", len(devices))
	}

	dev := devices[mkdev(252, 0)]
	if dev == nil {
		t.Fatal("device 252:0 not found")
	}
	if dev.Pool != "ocs-storagecluster" {
		t.Errorf("pool = %q, want %q", dev.Pool, "ocs-storagecluster")
	}
	if dev.ImageName != "csi-vol-abc" {
		t.Errorf("image = %q, want %q", dev.ImageName, "csi-vol-abc")
	}

	// Remove device 0 and rescan
	os.RemoveAll(dev0)
	if err := w.Scan(); err != nil {
		t.Fatalf("Scan() after removal error: %v", err)
	}
	devices = w.GetDevices()
	if len(devices) != 1 {
		t.Fatalf("after removal got %d devices, want 1", len(devices))
	}
}

func TestScanBadMajor(t *testing.T) {
	dir := t.TempDir()
	dev0 := filepath.Join(dir, "0")
	os.MkdirAll(dev0, 0o755)
	os.WriteFile(filepath.Join(dev0, "pool"), []byte("pool\n"), 0o644)
	os.WriteFile(filepath.Join(dev0, "name"), []byte("img\n"), 0o644)
	os.WriteFile(filepath.Join(dev0, "major"), []byte("notanumber\n"), 0o644)
	os.WriteFile(filepath.Join(dev0, "minor"), []byte("0\n"), 0o644)

	w := &Watcher{
		devices: make(map[uint32]*RBDDevice),
		sysPath: dir,
	}

	// Should not error at Scan level (device is skipped with warning), but no devices added
	if err := w.Scan(); err != nil {
		t.Fatalf("Scan() error: %v", err)
	}
	if len(w.GetDevices()) != 0 {
		t.Error("expected 0 devices when major is unparseable")
	}
}

func TestLookupByImageName(t *testing.T) {
	w := &Watcher{
		devices: map[uint32]*RBDDevice{
			mkdev(252, 0): {ID: "0", ImageName: "csi-vol-abc", Pool: "pool1"},
			mkdev(252, 1): {ID: "1", ImageName: "csi-vol-def", Pool: "pool2"},
		},
	}

	d := w.LookupByImageName("csi-vol-def")
	if d == nil || d.Pool != "pool2" {
		t.Errorf("LookupByImageName(csi-vol-def) = %v, want pool2 device", d)
	}

	d = w.LookupByImageName("nonexistent")
	if d != nil {
		t.Errorf("LookupByImageName(nonexistent) = %v, want nil", d)
	}
}
