VMLINUX  = bpf/vmlinux.h
PROTO    = proto/agent.proto
GOROOT  := /usr/local/go
GOPATH  := $(shell /usr/local/go/bin/go env GOPATH)
GOBIN    = $(GOPATH)/bin
GOEXE    = $(GOROOT)/bin/go
PROTOC_OPTS = --go_out=. --go_opt=module=agentscope \
              --go-grpc_out=. --go-grpc_opt=module=agentscope \
              --proto_path=proto

export PATH := $(GOROOT)/bin:$(GOBIN):$(PATH)

all: proto generate build

proto:
	mkdir -p gen/agent
	PATH=$(GOBIN):$$PATH protoc $(PROTOC_OPTS) $(PROTO)

$(VMLINUX):
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

generate: $(VMLINUX)
	$(GOEXE) generate ./internal/daemon/...

build:
	$(GOEXE) build -o agentscoped ./

clean:
	rm -f agentscoped bpf/vmlinux.h internal/daemon/ssl_trace_bpfel.go internal/daemon/ssl_trace_bpfeb.go internal/daemon/ssl_trace_bpfel.o internal/daemon/ssl_trace_bpfeb.o
	rm -rf gen/
