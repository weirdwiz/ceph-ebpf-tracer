package main

import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os/signal"
	"syscall"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/klog/v2"

	bpfpkg "github.com/weirdwiz/ceph-ebpf-tracer/pkg/bpf"
	"github.com/weirdwiz/ceph-ebpf-tracer/pkg/collector"
	"github.com/weirdwiz/ceph-ebpf-tracer/pkg/correlator"
	"github.com/weirdwiz/ceph-ebpf-tracer/pkg/device"
)

func main() {
	var (
		listenAddr string
		kubeconfig string
	)

	flag.StringVar(&listenAddr, "listen", ":9099", "address to serve Prometheus metrics on")
	flag.StringVar(&kubeconfig, "kubeconfig", "", "path to kubeconfig (uses in-cluster config if empty)")
	klog.InitFlags(nil)
	flag.Parse()

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	// Discover RBD major number
	rbdMajor, err := device.DiscoverRBDMajor()
	if err != nil {
		klog.Fatalf("discovering RBD major: %v", err)
	}
	klog.Infof("RBD major number: %d", rbdMajor)

	// Load and attach eBPF programs
	tracer, err := bpfpkg.Load(rbdMajor)
	if err != nil {
		klog.Fatalf("loading BPF: %v", err)
	}
	defer tracer.Close()

	if err := tracer.Attach(); err != nil {
		klog.Fatalf("attaching BPF: %v", err)
	}

	// Set up device watcher
	dw := device.NewWatcher()
	if err := dw.Scan(); err != nil {
		klog.Warningf("initial device scan: %v", err)
	}

	// Set up Kubernetes client
	k8sClient, err := buildK8sClient(kubeconfig)
	if err != nil {
		klog.Fatalf("building k8s client: %v", err)
	}

	// Set up PVC correlator
	cor := correlator.New(k8sClient)
	cor.Run(ctx)

	// Load and attach network tracer
	netTracer, err := bpfpkg.NewNetTracer()
	if err != nil {
		klog.Fatalf("loading net BPF: %v", err)
	}
	defer netTracer.Close()

	if err := netTracer.Attach(); err != nil {
		klog.Fatalf("attaching net BPF: %v", err)
	}

	// Set up Prometheus collectors
	maps := tracer.Maps()
	col := collector.New(dw, cor, maps.IoLatency, maps.IoThroughput, maps.IoSizeDist, maps.IoQueueDepth)
	prometheus.MustRegister(col)

	netMaps := netTracer.Maps()
	netCol := collector.NewNetCollector(netMaps.CephConnStats)
	prometheus.MustRegister(netCol)

	// Serve metrics
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "ok")
	})

	server := &http.Server{Addr: listenAddr, Handler: mux}

	go func() {
		klog.Infof("serving metrics on %s", listenAddr)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			klog.Fatalf("HTTP server: %v", err)
		}
	}()

	<-ctx.Done()
	klog.Info("shutting down")
	server.Close()
}

func buildK8sClient(kubeconfig string) (kubernetes.Interface, error) {
	var config *rest.Config
	var err error

	if kubeconfig != "" {
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
	} else {
		config, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, err
	}

	return kubernetes.NewForConfig(config)
}
