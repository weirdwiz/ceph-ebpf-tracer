package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"k8s.io/klog/v2"
)

// NetTracerHandle manages eBPF programs for Ceph network connection tracing.
type NetTracerHandle struct {
	objs  *NetTracerObjects
	links []link.Link
}

func NewNetTracer() (*NetTracerHandle, error) {
	objs := &NetTracerObjects{}
	if err := LoadNetTracerObjects(objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("loading net BPF objects: %w", err)
	}
	return &NetTracerHandle{objs: objs}, nil
}

func (t *NetTracerHandle) Attach() error {
	probeLink, err := link.Tracepoint("tcp", "tcp_probe", t.objs.TraceTcpProbe, nil)
	if err != nil {
		return fmt.Errorf("attaching tcp_probe tracepoint: %w", err)
	}
	t.links = append(t.links, probeLink)
	klog.Info("attached to tracepoint/tcp/tcp_probe")

	retransLink, err := link.Tracepoint("tcp", "tcp_retransmit_skb", t.objs.TraceTcpRetransmit, nil)
	if err != nil {
		return fmt.Errorf("attaching tcp_retransmit_skb tracepoint: %w", err)
	}
	t.links = append(t.links, retransLink)
	klog.Info("attached to tracepoint/tcp/tcp_retransmit_skb")

	return nil
}

func (t *NetTracerHandle) Maps() *NetTracerMaps {
	return &t.objs.NetTracerMaps
}

func (t *NetTracerHandle) Close() {
	for _, l := range t.links {
		if err := l.Close(); err != nil {
			klog.Errorf("closing net BPF link: %v", err)
		}
	}
	if t.objs != nil {
		if err := t.objs.Close(); err != nil {
			klog.Errorf("closing net BPF objects: %v", err)
		}
	}
}
