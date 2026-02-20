package collector

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"

	"github.com/cilium/ebpf"
	"github.com/prometheus/client_golang/prometheus"
)

// BPF map types for network tracing -- must match C structs.
type connKey struct {
	Daddr uint32
	Dport uint16
	Pad   uint16
}

type connStats struct {
	SrttSumUS  uint64
	SrttCount  uint64
	SrttMinUS  uint32
	SrttMaxUS  uint32
	Retransmits uint64
	BytesSent  uint64
	LastCwnd   uint32
	LastSndWnd uint32
}

// NetCollector exports per-OSD Ceph network metrics.
type NetCollector struct {
	connMap  *ebpf.Map
	nodeName string

	rttAvg       *prometheus.Desc
	rttMin       *prometheus.Desc
	rttMax       *prometheus.Desc
	retransmits  *prometheus.Desc
	bytesSent    *prometheus.Desc
	cwnd         *prometheus.Desc
}

func NewNetCollector(connMap *ebpf.Map) *NetCollector {
	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		nodeName, _ = os.Hostname()
	}

	labels := []string{"peer", "port", "node"}

	return &NetCollector{
		connMap:  connMap,
		nodeName: nodeName,
		rttAvg: prometheus.NewDesc(
			"ceph_ebpf_network_rtt_seconds",
			"Average TCP smoothed RTT to Ceph OSD/MON peer in seconds",
			labels, nil,
		),
		rttMin: prometheus.NewDesc(
			"ceph_ebpf_network_rtt_min_seconds",
			"Minimum observed TCP RTT to Ceph peer in seconds",
			labels, nil,
		),
		rttMax: prometheus.NewDesc(
			"ceph_ebpf_network_rtt_max_seconds",
			"Maximum observed TCP RTT to Ceph peer in seconds",
			labels, nil,
		),
		retransmits: prometheus.NewDesc(
			"ceph_ebpf_network_retransmits_total",
			"Total TCP retransmissions to Ceph peer",
			labels, nil,
		),
		bytesSent: prometheus.NewDesc(
			"ceph_ebpf_network_bytes_sent_total",
			"Total bytes sent to Ceph peer",
			labels, nil,
		),
		cwnd: prometheus.NewDesc(
			"ceph_ebpf_network_cwnd",
			"Current TCP congestion window to Ceph peer (in segments)",
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

	iter := c.connMap.Iterate()
	for iter.Next(&key, &stats) {
		peer := ipv4String(key.Daddr)
		port := fmt.Sprintf("%d", key.Dport)

		if stats.SrttCount > 0 {
			avgRttSec := float64(stats.SrttSumUS) / float64(stats.SrttCount) / 1e6
			ch <- prometheus.MustNewConstMetric(
				c.rttAvg, prometheus.GaugeValue, avgRttSec,
				peer, port, c.nodeName,
			)
		}

		if stats.SrttMinUS > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.rttMin, prometheus.GaugeValue, float64(stats.SrttMinUS)/1e6,
				peer, port, c.nodeName,
			)
		}

		if stats.SrttMaxUS > 0 {
			ch <- prometheus.MustNewConstMetric(
				c.rttMax, prometheus.GaugeValue, float64(stats.SrttMaxUS)/1e6,
				peer, port, c.nodeName,
			)
		}

		ch <- prometheus.MustNewConstMetric(
			c.retransmits, prometheus.CounterValue, float64(stats.Retransmits),
			peer, port, c.nodeName,
		)

		ch <- prometheus.MustNewConstMetric(
			c.bytesSent, prometheus.CounterValue, float64(stats.BytesSent),
			peer, port, c.nodeName,
		)

		ch <- prometheus.MustNewConstMetric(
			c.cwnd, prometheus.GaugeValue, float64(stats.LastCwnd),
			peer, port, c.nodeName,
		)
	}
}

func ipv4String(addr uint32) string {
	ip := make(net.IP, 4)
	binary.LittleEndian.PutUint32(ip, addr)
	return ip.String()
}
