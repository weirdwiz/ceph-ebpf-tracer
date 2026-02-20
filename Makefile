IMAGE ?= quay.io/dkamboj/ceph-ebpf-tracer
TAG ?= latest

.PHONY: generate build image push deploy clean

generate:
	cd pkg/bpf && go generate ./...

build: generate
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o bin/ceph-ebpf-tracer ./cmd/tracer/

image:
	podman build --platform linux/amd64 -t $(IMAGE):$(TAG) .

push: image
	podman push $(IMAGE):$(TAG)

deploy:
	kubectl apply -f deploy/rbac.yaml
	kubectl apply -f deploy/daemonset.yaml
	kubectl apply -f deploy/servicemonitor.yaml

undeploy:
	kubectl delete -f deploy/servicemonitor.yaml --ignore-not-found
	kubectl delete -f deploy/daemonset.yaml --ignore-not-found
	kubectl delete -f deploy/rbac.yaml --ignore-not-found

clean:
	rm -rf bin/
	rm -f pkg/bpf/tracer_bpfel_x86.go pkg/bpf/tracer_bpfel_x86.o
