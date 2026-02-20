package bpf

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"k8s.io/klog/v2"
)

// Tracer manages the lifecycle of eBPF programs and maps for RBD I/O tracing.
type Tracer struct {
	objs  *TracerObjects
	links []link.Link
}

// Load compiles and loads the eBPF programs into the kernel, setting the
// RBD major number for device filtering.
func Load(rbdMajor uint32) (*Tracer, error) {
	spec, err := LoadTracer()
	if err != nil {
		return nil, fmt.Errorf("loading BPF spec: %w", err)
	}

	// Set the RBD major number constant before loading
	if err := spec.RewriteConstants(map[string]interface{}{
		"rbd_major": rbdMajor,
	}); err != nil {
		return nil, fmt.Errorf("rewriting rbd_major constant: %w", err)
	}

	objs := &TracerObjects{}
	if err := spec.LoadAndAssign(objs, &ebpf.CollectionOptions{}); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	return &Tracer{objs: objs}, nil
}

// Attach attaches the eBPF programs to their respective tracepoints.
func (t *Tracer) Attach() error {
	issueLink, err := link.Tracepoint("block", "block_rq_issue", t.objs.TraceBlockRqIssue, nil)
	if err != nil {
		return fmt.Errorf("attaching block_rq_issue tracepoint: %w", err)
	}
	t.links = append(t.links, issueLink)
	klog.Info("attached to tracepoint/block/block_rq_issue")

	completeLink, err := link.Tracepoint("block", "block_rq_complete", t.objs.TraceBlockRqComplete, nil)
	if err != nil {
		return fmt.Errorf("attaching block_rq_complete tracepoint: %w", err)
	}
	t.links = append(t.links, completeLink)
	klog.Info("attached to tracepoint/block/block_rq_complete")

	return nil
}

// Maps returns the BPF maps for reading from userspace.
func (t *Tracer) Maps() *TracerMaps {
	return &t.objs.TracerMaps
}

// Close detaches all tracepoints and frees BPF resources.
func (t *Tracer) Close() {
	for _, l := range t.links {
		if err := l.Close(); err != nil {
			klog.Errorf("closing BPF link: %v", err)
		}
	}
	if t.objs != nil {
		if err := t.objs.Close(); err != nil {
			klog.Errorf("closing BPF objects: %v", err)
		}
	}
}
