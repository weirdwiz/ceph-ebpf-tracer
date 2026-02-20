package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86 -I/usr/include/x86_64-linux-gnu" NetTracer ../../bpf/net_tracer.c -- -I../../bpf
