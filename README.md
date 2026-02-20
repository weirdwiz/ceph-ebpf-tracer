# ceph-ebpf-tracer

eBPF-based tracing for Ceph RBD on OpenShift Data Foundation (ODF) clusters. Attaches to kernel tracepoints to collect per-PVC I/O latency, throughput, queue depth, and per-daemon TCP network metrics without any Ceph-side changes.

## What it does

Two eBPF programs run in the kernel on each storage node:

**Block I/O tracer** (`bpf/tracer.c`) -- attaches to `block_rq_issue` and `block_rq_complete` tracepoints, filters by the RBD kernel module's major number, and records per-device latency histograms, throughput counters, I/O size distributions, and queue depth. The Go userspace correlates device numbers to PVC names via sysfs and the Kubernetes PV API.

**Network tracer** (`bpf/net_tracer.c`) -- attaches to `tcp_probe` and `tcp_retransmit_skb` tracepoints, filters by Ceph ports (3300, 6789, 6800-7300), and tracks per-connection RTT, retransmissions, bytes sent, and congestion window. The Go userspace resolves peer IPs to Ceph daemon identities (OSD, MON, MGR, MDS) by watching pods and services via the Kubernetes API, then aggregates stats per daemon pair.

## Metrics

### RBD block I/O metrics

Labels: `pvc`, `namespace`, `pool`, `node`, `operation` (read/write)

| Metric | Type | Description |
|--------|------|-------------|
| `ceph_ebpf_rbd_io_latency_seconds` | histogram | I/O latency distribution (log2 buckets from ~1us to ~30s) |
| `ceph_ebpf_rbd_io_bytes_total` | counter | Total bytes read/written per PVC |
| `ceph_ebpf_rbd_io_ops_total` | counter | Total I/O operations per PVC |
| `ceph_ebpf_rbd_io_size_bytes` | histogram | I/O request size distribution |
| `ceph_ebpf_rbd_queue_depth` | gauge | Current inflight I/O requests |
| `ceph_ebpf_rbd_io_errors_total` | counter | I/O completions with non-zero error status |

### Network metrics

Labels: `source_type`, `source_id`, `dest_type`, `dest_id`, `node`

Type/ID values: `osd`/`osd-0`, `mon`/`mon-a`, `mgr`/`mgr-a`, `mds`/`mds-ocs`, `client`/`client`

| Metric | Type | Description |
|--------|------|-------------|
| `ceph_ebpf_network_rtt_seconds` | gauge | Weighted average TCP smoothed RTT per daemon pair |
| `ceph_ebpf_network_rtt_min_seconds` | gauge | Minimum observed RTT across connections |
| `ceph_ebpf_network_rtt_max_seconds` | gauge | Maximum observed RTT across connections |
| `ceph_ebpf_network_retransmits_total` | counter | TCP retransmissions per daemon pair |
| `ceph_ebpf_network_bytes_sent_total` | counter | Bytes sent per daemon pair |
| `ceph_ebpf_network_cwnd` | gauge | Max TCP congestion window across connections (segments) |

## Requirements

- OpenShift 4.14+ with ODF 4.14+ (tested on OCP 4.21 / ODF 4.21)
- Kernel 5.14+ (RHCOS ships this)
- RBD kernel module loaded (ODF maps RBD volumes automatically)
- Privileged DaemonSet access on storage nodes

## Deploy on an ODF cluster

```bash
# Apply SecurityContextConstraints (required for privileged + hostPID)
oc apply -f deploy/scc.yaml

# Create ServiceAccount, ClusterRole, ClusterRoleBinding
oc apply -f deploy/rbac.yaml

# Deploy the DaemonSet (runs on nodes labeled cluster.ocs.openshift.io/openshift-storage)
oc apply -f deploy/daemonset.yaml

# Create Service + ServiceMonitor for Prometheus scraping
oc apply -f deploy/servicemonitor.yaml
```

Or use the Makefile:

```bash
make deploy
```

Verify it's running:

```bash
oc -n openshift-storage get pods -l app.kubernetes.io/name=ceph-ebpf-tracer
oc -n openshift-storage logs daemonset/ceph-ebpf-tracer --tail=20
```

You should see:

```
attached to tracepoint/block/block_rq_issue
attached to tracepoint/block/block_rq_complete
correlator synced N RBD PVs
resolver synced N Ceph daemon IPs
attached to tracepoint/tcp/tcp_probe
attached to tracepoint/tcp/tcp_retransmit_skb
serving metrics on :9099
```

## Querying metrics

Metrics are available at `:9099/metrics` on each tracer pod. If the ServiceMonitor is deployed, Prometheus scrapes them automatically.

**OpenShift Console**: Navigate to Observe > Metrics and run:

```promql
# P95 RBD I/O latency per PVC
histogram_quantile(0.95, rate(ceph_ebpf_rbd_io_latency_seconds_bucket[5m]))

# IOPS per PVC
rate(ceph_ebpf_rbd_io_ops_total[5m])

# Throughput per PVC
rate(ceph_ebpf_rbd_io_bytes_total[5m])

# RTT to OSDs from this node
ceph_ebpf_network_rtt_seconds{dest_type="osd"}

# OSD-to-OSD replication RTT (cross-node)
ceph_ebpf_network_rtt_seconds{source_type="osd", dest_type="osd"}

# Retransmit rate to any Ceph daemon
rate(ceph_ebpf_network_retransmits_total[5m])

# Client-to-MON latency
ceph_ebpf_network_rtt_seconds{source_type="client", dest_type="mon"}
```

## Build from source

Requires: Go 1.23+, podman (or docker), clang/llvm/libbpf-dev (for BPF compilation inside the container build).

```bash
# Build the container image (compiles BPF + Go inside the container)
make image

# Push to your registry
IMAGE=quay.io/youruser/ceph-ebpf-tracer TAG=latest make push
```

To build locally (requires Linux with BPF toolchain):

```bash
make generate  # compile BPF C -> Go bindings
make build     # build the Go binary
```

## Run tests

```bash
go test ./pkg/device/ ./pkg/correlator/ ./pkg/resolver/
```

## Architecture

```
kernel                          userspace                        prometheus
--------                        ---------                        ----------
block_rq_issue ──┐
block_rq_complete┘─→ BPF maps ─→ Collector ──→ /metrics
                     (per-dev)    + sysfs scan (dev -> image)
                                  + PV watch   (image -> PVC)

tcp_probe ───────┐
tcp_retransmit ──┘─→ BPF map ──→ NetCollector ─→ /metrics
                     (per-conn)   + pod watch  (IP -> daemon role)
                                  + svc watch  (ClusterIP -> mon)
                                  + aggregate per daemon pair
```

The tracer runs as a privileged DaemonSet with `hostPID: true`. BPF tracepoints fire in the host kernel and see traffic from all pods on the node regardless of network namespace.

## Cleanup

```bash
make undeploy
```

## Project layout

```
bpf/
  tracer.c          # BPF program for RBD block I/O tracing
  net_tracer.c      # BPF program for Ceph network tracing
  vmlinux.h         # kernel type definitions
cmd/tracer/
  main.go           # entrypoint, wires everything together
pkg/
  bpf/              # BPF loader, go:generate directives
  collector/        # Prometheus collectors (block I/O + network)
  correlator/       # PV watcher: RBD image name -> PVC identity
  device/           # sysfs scanner: /sys/devices/rbd/ -> device info
  resolver/         # pod/svc watcher: IP -> Ceph daemon role
deploy/
  daemonset.yaml    # DaemonSet (runs on ODF storage nodes)
  rbac.yaml         # ServiceAccount, ClusterRole, ClusterRoleBinding
  scc.yaml          # SecurityContextConstraints for OpenShift
  servicemonitor.yaml  # Prometheus ServiceMonitor + headless Service
  test-workload.yaml   # fio test pod + PVC for generating I/O
```
