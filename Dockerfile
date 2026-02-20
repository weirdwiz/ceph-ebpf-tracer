FROM golang:1.23-bookworm AS builder

# Install BPF toolchain
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy go module files first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy source
COPY . .

# Generate BPF bytecode and Go bindings
RUN cd pkg/bpf && go generate ./...

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-s -w" \
    -o /ceph-ebpf-tracer \
    ./cmd/tracer/

# Runtime image -- minimal
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder /ceph-ebpf-tracer /ceph-ebpf-tracer

ENTRYPOINT ["/ceph-ebpf-tracer"]
