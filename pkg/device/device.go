package device

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"k8s.io/klog/v2"
)

const (
	sysRBDPath = "/sys/devices/rbd"
	procDevices = "/proc/devices"
)

// RBDDevice holds the sysfs-derived info for a mapped RBD device.
type RBDDevice struct {
	ID        string // sysfs ID (e.g., "0")
	Pool      string
	ImageName string
	PoolNS    string
	Major     uint32
	Minor     uint32
	Dev       uint32 // encoded as MKDEV(major, minor)
}

// Watcher discovers RBD devices on the node by reading sysfs.
type Watcher struct {
	mu      sync.RWMutex
	devices map[uint32]*RBDDevice // keyed by Dev (MKDEV)
	sysPath string
}

func NewWatcher() *Watcher {
	return &Watcher{
		devices: make(map[uint32]*RBDDevice),
		sysPath: sysRBDPath,
	}
}

// DiscoverRBDMajor reads /proc/devices to find the major number for "rbd".
func DiscoverRBDMajor() (uint32, error) {
	data, err := os.ReadFile(procDevices)
	if err != nil {
		return 0, fmt.Errorf("reading %s: %w", procDevices, err)
	}

	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == "rbd" {
			major, err := strconv.ParseUint(fields[0], 10, 32)
			if err != nil {
				return 0, fmt.Errorf("parsing rbd major: %w", err)
			}
			return uint32(major), nil
		}
	}

	return 0, fmt.Errorf("rbd not found in %s -- is the rbd kernel module loaded?", procDevices)
}

// mkdev encodes major/minor into a single u32, matching the kernel's MKDEV macro.
func mkdev(major, minor uint32) uint32 {
	return (major << 20) | minor
}

// Scan reads /sys/devices/rbd/<N>/ entries and populates the device map.
func (w *Watcher) Scan() error {
	entries, err := os.ReadDir(w.sysPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", w.sysPath, err)
	}

	w.mu.Lock()
	defer w.mu.Unlock()

	seen := make(map[uint32]bool)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}

		id := entry.Name()
		// Skip non-numeric directories
		if _, err := strconv.Atoi(id); err != nil {
			continue
		}

		dev, err := w.readDevice(id)
		if err != nil {
			klog.Warningf("skipping rbd device %s: %v", id, err)
			continue
		}

		if _, exists := w.devices[dev.Dev]; !exists {
			klog.Infof("discovered rbd device %s: %s/%s (dev %d:%d)",
				id, dev.Pool, dev.ImageName, dev.Major, dev.Minor)
		}
		w.devices[dev.Dev] = dev
		seen[dev.Dev] = true
	}

	// Remove devices that no longer exist
	for dev := range w.devices {
		if !seen[dev] {
			klog.V(2).Infof("removing stale rbd device %d:%d", dev>>20, dev&0xFFFFF)
			delete(w.devices, dev)
		}
	}

	return nil
}

func (w *Watcher) readDevice(id string) (*RBDDevice, error) {
	base := filepath.Join(w.sysPath, id)

	pool, err := readSysfs(filepath.Join(base, "pool"))
	if err != nil {
		return nil, fmt.Errorf("reading pool: %w", err)
	}

	name, err := readSysfs(filepath.Join(base, "name"))
	if err != nil {
		return nil, fmt.Errorf("reading name: %w", err)
	}

	majorStr, err := readSysfs(filepath.Join(base, "major"))
	if err != nil {
		return nil, fmt.Errorf("reading major: %w", err)
	}
	major, _ := strconv.ParseUint(majorStr, 10, 32)

	minorStr, err := readSysfs(filepath.Join(base, "minor"))
	if err != nil {
		return nil, fmt.Errorf("reading minor: %w", err)
	}
	minor, _ := strconv.ParseUint(minorStr, 10, 32)

	poolNS, _ := readSysfs(filepath.Join(base, "pool_ns"))

	return &RBDDevice{
		ID:        id,
		Pool:      pool,
		ImageName: name,
		PoolNS:    poolNS,
		Major:     uint32(major),
		Minor:     uint32(minor),
		Dev:       mkdev(uint32(major), uint32(minor)),
	}, nil
}

func readSysfs(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(data)), nil
}

// GetDevices returns a snapshot of all discovered RBD devices, keyed by Dev.
func (w *Watcher) GetDevices() map[uint32]*RBDDevice {
	w.mu.RLock()
	defer w.mu.RUnlock()

	result := make(map[uint32]*RBDDevice, len(w.devices))
	for k, v := range w.devices {
		result[k] = v
	}
	return result
}

// LookupByImageName finds a device by its RBD image name.
func (w *Watcher) LookupByImageName(imageName string) *RBDDevice {
	w.mu.RLock()
	defer w.mu.RUnlock()

	for _, dev := range w.devices {
		if dev.ImageName == imageName {
			return dev
		}
	}
	return nil
}
