package collector

import (
	"encoding/binary"
	"net"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/klog/v2"

	"github.com/weirdwiz/ceph-ebpf-tracer/pkg/resolver"
)

// BPF map types for network tracing -- must match C structs.
type connKey struct {
	Saddr uint32
	Daddr uint32
	Sport uint16
	Dport uint16
}

type connStats struct {
	SrttSumUS   uint64
	SrttCount   uint64
	SrttMinUS   uint32
	SrttMaxUS   uint32
	Retransmits uint64
	BytesSent   uint64
	LastCwnd    uint32
	LastSndWnd  uint32
}

// pairKey identifies a unique source/dest daemon pair for aggregation.
type pairKey struct {
	srcType, srcID string
	dstType, dstID string
}

// pairStats aggregates stats across multiple TCP connections between the same daemon pair.
type pairStats struct {
	srttSumUS   uint64
	srttCount   uint64
	srttMinUS   uint32
	srttMaxUS   uint32
	retransmits uint64
	bytesSent   uint64
	maxCwnd     uint32
}

// NetCollector exports per-daemon-pair Ceph network metrics,
// filtered to only known Ceph daemon connections.
type NetCollector struct {
	connMap  *ebpf.Map
	resolver *resolver.Resolver
	nodeName string

	rttAvg      *prometheus.Desc
	rttMin      *prometheus.Desc
	rttMax      *prometheus.Desc
	retransmits *prometheus.Desc
	bytesSent   *prometheus.Desc
	cwnd        *prometheus.Desc
}

func NewNetCollector(connMap *ebpf.Map, res *resolver.Resolver, nodeName string) *NetCollector {
	labels := []string{"source_type", "source_id", "dest_type", "dest_id", "node"}

	return &NetCollector{
		connMap:  connMap,
		resolver: res,
		nodeName: nodeName,
		rttAvg: prometheus.NewDesc(
			"ceph_ebpf_network_rtt_seconds",
			"Weighted average TCP smoothed RTT per Ceph daemon pair in seconds",
			labels, nil,
		),
		rttMin: prometheus.NewDesc(
			"ceph_ebpf_network_rtt_min_seconds",
			"Minimum observed TCP RTT per Ceph daemon pair in seconds",
			labels, nil,
		),
		rttMax: prometheus.NewDesc(
			"ceph_ebpf_network_rtt_max_seconds",
			"Maximum observed TCP RTT per Ceph daemon pair in seconds",
			labels, nil,
		),
		retransmits: prometheus.NewDesc(
			"ceph_ebpf_network_retransmits_total",
			"Total TCP retransmissions per Ceph daemon pair",
			labels, nil,
		),
		bytesSent: prometheus.NewDesc(
			"ceph_ebpf_network_bytes_sent_total",
			"Total bytes sent per Ceph daemon pair",
			labels, nil,
		),
		cwnd: prometheus.NewDesc(
			"ceph_ebpf_network_cwnd",
			"Maximum TCP congestion window across connections to Ceph daemon pair (segments)",
			labels, nil,
		),
	}
}

func (c *NetCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.rttAvg
	ch <- c.rttMin
	ch <- c.rttMax
	ch <- c.retransmits
	ch <- c.bytesSent
	ch <- c.cwnd
}

func (c *NetCollector) Collect(ch chan<- prometheus.Metric) {
	var key connKey
	var stats connStats

	// First pass: aggregate per daemon pair.
	pairs := make(map[pairKey]*pairStats)

	iter := c.connMap.Iterate()
	for iter.Next(&key, &stats) {
		srcIP := ipv4String(key.Saddr)
		dstIP := ipv4String(key.Daddr)

		srcInfo := c.resolver.Lookup(srcIP)
		dstInfo := c.resolver.Lookup(dstIP)

		if srcInfo == nil && dstInfo == nil {
			continue
		}

		pk := pairKey{srcType: "client", srcID: "client", dstType: "client", dstID: "client"}
		if srcInfo != nil {
			pk.srcType = srcInfo.Role
			pk.srcID = srcInfo.DaemonID
		}
		if dstInfo != nil {
			pk.dstType = dstInfo.Role
			pk.dstID = dstInfo.DaemonID
		}

		ps, ok := pairs[pk]
		if !ok {
			ps = &pairStats{srttMinUS: stats.SrttMinUS}
			pairs[pk] = ps
		}

		ps.srttSumUS += stats.SrttSumUS
		ps.srttCount += stats.SrttCount
		ps.retransmits += stats.Retransmits
		ps.bytesSent += stats.BytesSent

		if stats.SrttMinUS > 0 && (stats.SrttMinUS < ps.srttMinUS || ps.srttMinUS == 0) {
			ps.srttMinUS = stats.SrttMinUS
		}
		if stats.SrttMaxUS > ps.srttMaxUS {
			ps.srttMaxUS = stats.SrttMaxUS
		}
		if stats.LastCwnd > ps.maxCwnd {
			ps.maxCwnd = stats.LastCwnd
		}
	}
	if err := iter.Err(); err != nil {
		klog.Warningf("iterating ceph_conn_stats map: %v", err)
	}

	// Second pass: emit one metric set per daemon pair.
	for pk, ps := range pairs {
		if ps.srttCount > 0 {
			avgRttSec := float64(ps.srttSumUS) / float64(ps.srttCount) / 1e6
			ch <- prometheus.MustNewConstMetric(
				c.rttAvg, prometheus.GaugeValue, avgRttSec,
				pk.srcType, pk.srcID, pk.dstType, pk.dstID, c.nodeName,
			)
		}

		if ps.srttMinUS > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.rttMin, prometheus.GaugeValue, float64(ps.srttMinUS)/1e6,
				pk.srcType, pk.srcID, pk.dstType, pk.dstID, c.nodeName,
			)
		}

		if ps.srttMaxUS > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.rttMax, prometheus.GaugeValue, float64(ps.srttMaxUS)/1e6,
				pk.srcType, pk.srcID, pk.dstType, pk.dstID, c.nodeName,
			)
		}

		ch <- prometheus.MustNewConstMetric(
			c.retransmits, prometheus.CounterValue, float64(ps.retransmits),
			pk.srcType, pk.srcID, pk.dstType, pk.dstID, c.nodeName,
		)

		ch <- prometheus.MustNewConstMetric(
			c.bytesSent, prometheus.CounterValue, float64(ps.bytesSent),
			pk.srcType, pk.srcID, pk.dstType, pk.dstID, c.nodeName,
		)

		ch <- prometheus.MustNewConstMetric(
			c.cwnd, prometheus.GaugeValue, float64(ps.maxCwnd),
			pk.srcType, pk.srcID, pk.dstType, pk.dstID, c.nodeName,
		)
	}
}

func ipv4String(addr uint32) string {
	ip := make(net.IP, 4)
	binary.NativeEndian.PutUint32(ip, addr)
	return ip.String()
}
