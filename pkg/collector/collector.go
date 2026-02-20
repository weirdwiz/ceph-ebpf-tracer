package collector

import (
	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"

	"github.com/weirdwiz/ceph-ebpf-tracer/pkg/correlator"
	"github.com/weirdwiz/ceph-ebpf-tracer/pkg/device"
)

const (
	opRead  = 0
	opWrite = 1

	log2BucketCount   = 32
	iosizeBucketCount = 16
)

// BPF map key/value types -- must match the C structs exactly.
type devOpKey struct {
	Dev uint32
	Op  uint8
	Pad [3]uint8
}

type devKey struct {
	Dev uint32
	Pad uint32
}

type latencyHist struct {
	Buckets [log2BucketCount]uint64
	TotalNS uint64
	Count   uint64
}

type ioStats struct {
	Bytes uint64
	Ops   uint64
}

type iosizeHist struct {
	ReadBuckets   [iosizeBucketCount]uint64
	WriteBuckets  [iosizeBucketCount]uint64
	ReadSumBytes  uint64
	WriteSumBytes uint64
}

type queueDepth struct {
	Inflight int64
	Errors   uint64
}

type Collector struct {
	deviceWatcher *device.Watcher
	correlator    *correlator.Correlator
	latencyMap    *ebpf.Map
	throughputMap *ebpf.Map
	iosizeMap     *ebpf.Map
	queueMap      *ebpf.Map
	nodeName      string

	ioLatency     *prometheus.Desc
	ioBytesTotal  *prometheus.Desc
	ioOpsTotal    *prometheus.Desc
	ioQueueDepth  *prometheus.Desc
	ioErrorsTotal *prometheus.Desc
	ioSizeDist    *prometheus.Desc
}

func New(
	dw *device.Watcher,
	cor *correlator.Correlator,
	nodeName string,
	latencyMap *ebpf.Map,
	throughputMap *ebpf.Map,
	iosizeMap *ebpf.Map,
	queueMap *ebpf.Map,
) *Collector {
	pvcLabels := []string{"pvc", "namespace", "pool", "node"}
	pvcOpLabels := []string{"pvc", "namespace", "pool", "node", "operation"}

	return &Collector{
		deviceWatcher: dw,
		correlator:    cor,
		latencyMap:    latencyMap,
		throughputMap: throughputMap,
		iosizeMap:     iosizeMap,
		queueMap:      queueMap,
		nodeName:      nodeName,

		ioLatency: prometheus.NewDesc(
			"ceph_ebpf_rbd_io_latency_seconds",
			"Histogram of RBD I/O latency in seconds, traced via eBPF block tracepoints",
			pvcOpLabels, nil,
		),
		ioBytesTotal: prometheus.NewDesc(
			"ceph_ebpf_rbd_io_bytes_total",
			"Total bytes of RBD I/O, traced via eBPF block tracepoints",
			pvcOpLabels, nil,
		),
		ioOpsTotal: prometheus.NewDesc(
			"ceph_ebpf_rbd_io_ops_total",
			"Total RBD I/O operations, traced via eBPF block tracepoints",
			pvcOpLabels, nil,
		),
		ioQueueDepth: prometheus.NewDesc(
			"ceph_ebpf_rbd_queue_depth",
			"Current number of inflight I/O requests to an RBD device",
			pvcLabels, nil,
		),
		ioErrorsTotal: prometheus.NewDesc(
			"ceph_ebpf_rbd_io_errors_total",
			"Total RBD I/O errors (non-zero completion status)",
			pvcLabels, nil,
		),
		ioSizeDist: prometheus.NewDesc(
			"ceph_ebpf_rbd_io_size_bytes",
			"Histogram of RBD I/O request sizes in bytes",
			pvcOpLabels, nil,
		),
	}
}

func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.ioLatency
	ch <- c.ioBytesTotal
	ch <- c.ioOpsTotal
	ch <- c.ioQueueDepth
	ch <- c.ioErrorsTotal
	ch <- c.ioSizeDist
}

func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	devices := c.deviceWatcher.GetDevices()

	c.collectLatency(ch, devices)
	c.collectThroughput(ch, devices)
	c.collectQueueDepth(ch, devices)
	c.collectIOSizeDist(ch, devices)
}

// resolveDevice maps a BPF dev number to PVC info. Returns nil if unmappable.
func (c *Collector) resolveDevice(dev uint32, devices map[uint32]*device.RBDDevice) (*device.RBDDevice, *correlator.PVCInfo) {
	d, ok := devices[dev]
	if !ok {
		return nil, nil
	}
	pvc := c.correlator.Lookup(d.ImageName)
	return d, pvc
}

func (c *Collector) collectLatency(ch chan<- prometheus.Metric, devices map[uint32]*device.RBDDevice) {
	var key devOpKey
	var hist latencyHist

	iter := c.latencyMap.Iterate()
	for iter.Next(&key, &hist) {
		_, pvc := c.resolveDevice(key.Dev, devices)
		if pvc == nil {
			continue
		}

		opStr := opString(key.Op)

		buckets := make(map[float64]uint64)
		var cumCount uint64
		for i := 0; i < log2BucketCount; i++ {
			cumCount += hist.Buckets[i]
			upperNS := uint64(1) << uint(i+1)
			upperSec := float64(upperNS) / 1e9
			buckets[upperSec] = cumCount
		}

		sumSec := float64(hist.TotalNS) / 1e9

		ch <- prometheus.MustNewConstHistogram(
			c.ioLatency,
			hist.Count, sumSec, buckets,
			pvc.PVCName, pvc.PVCNamespace, pvc.Pool, c.nodeName, opStr,
		)
	}
	if err := iter.Err(); err != nil {
		klog.Warningf("iterating io_latency map: %v", err)
	}
}

func (c *Collector) collectThroughput(ch chan<- prometheus.Metric, devices map[uint32]*device.RBDDevice) {
	var key devOpKey
	// io_throughput is a BPF_MAP_TYPE_PERCPU_HASH. cilium/ebpf's Iterate().Next()
	// populates a slice with one ioStats value per CPU when the value arg is a slice type.
	var values []ioStats

	iter := c.throughputMap.Iterate()
	for iter.Next(&key, &values) {
		_, pvc := c.resolveDevice(key.Dev, devices)
		if pvc == nil {
			continue
		}

		var totalBytes, totalOps uint64
		for _, v := range values {
			totalBytes += v.Bytes
			totalOps += v.Ops
		}

		opStr := opString(key.Op)

		ch <- prometheus.MustNewConstMetric(
			c.ioBytesTotal, prometheus.CounterValue, float64(totalBytes),
			pvc.PVCName, pvc.PVCNamespace, pvc.Pool, c.nodeName, opStr,
		)
		ch <- prometheus.MustNewConstMetric(
			c.ioOpsTotal, prometheus.CounterValue, float64(totalOps),
			pvc.PVCName, pvc.PVCNamespace, pvc.Pool, c.nodeName, opStr,
		)
	}
	if err := iter.Err(); err != nil {
		klog.Warningf("iterating io_throughput map: %v", err)
	}
}

func (c *Collector) collectQueueDepth(ch chan<- prometheus.Metric, devices map[uint32]*device.RBDDevice) {
	var key devKey
	var qd queueDepth

	iter := c.queueMap.Iterate()
	for iter.Next(&key, &qd) {
		_, pvc := c.resolveDevice(key.Dev, devices)
		if pvc == nil {
			continue
		}

		inflight := qd.Inflight
		if inflight < 0 {
			inflight = 0
		}

		ch <- prometheus.MustNewConstMetric(
			c.ioQueueDepth, prometheus.GaugeValue, float64(inflight),
			pvc.PVCName, pvc.PVCNamespace, pvc.Pool, c.nodeName,
		)
		ch <- prometheus.MustNewConstMetric(
			c.ioErrorsTotal, prometheus.CounterValue, float64(qd.Errors),
			pvc.PVCName, pvc.PVCNamespace, pvc.Pool, c.nodeName,
		)
	}
	if err := iter.Err(); err != nil {
		klog.Warningf("iterating io_queue_depth map: %v", err)
	}
}

func (c *Collector) collectIOSizeDist(ch chan<- prometheus.Metric, devices map[uint32]*device.RBDDevice) {
	var key devKey
	var sh iosizeHist

	iter := c.iosizeMap.Iterate()
	for iter.Next(&key, &sh) {
		_, pvc := c.resolveDevice(key.Dev, devices)
		if pvc == nil {
			continue
		}

		// Read I/O size histogram
		readBuckets := make(map[float64]uint64)
		var readTotal uint64
		for i := 0; i < iosizeBucketCount; i++ {
			readTotal += sh.ReadBuckets[i]
			upperBytes := float64(uint64(1) << uint(i+1))
			readBuckets[upperBytes] = readTotal
		}
		if readTotal > 0 {
			ch <- prometheus.MustNewConstHistogram(
				c.ioSizeDist,
				readTotal, float64(sh.ReadSumBytes), readBuckets,
				pvc.PVCName, pvc.PVCNamespace, pvc.Pool, c.nodeName, "read",
			)
		}

		// Write I/O size histogram
		writeBuckets := make(map[float64]uint64)
		var writeTotal uint64
		for i := 0; i < iosizeBucketCount; i++ {
			writeTotal += sh.WriteBuckets[i]
			upperBytes := float64(uint64(1) << uint(i+1))
			writeBuckets[upperBytes] = writeTotal
		}
		if writeTotal > 0 {
			ch <- prometheus.MustNewConstHistogram(
				c.ioSizeDist,
				writeTotal, float64(sh.WriteSumBytes), writeBuckets,
				pvc.PVCName, pvc.PVCNamespace, pvc.Pool, c.nodeName, "write",
			)
		}
	}
	if err := iter.Err(); err != nil {
		klog.Warningf("iterating io_size_dist map: %v", err)
	}
}

func opString(op uint8) string {
	if op == opWrite {
		return "write"
	}
	return "read"
}
