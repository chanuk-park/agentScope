#!/usr/bin/env bash
set -e

echo "=== [1/5] 시스템 패키지 ==="
sudo apt-get update -qq
sudo apt-get install -y \
    clang llvm \
    libbpf-dev \
    linux-headers-$(uname -r) \
    linux-tools-$(uname -r) \
    linux-tools-common \
    protobuf-compiler \
    build-essential \
    git curl

echo "=== [2/5] Go 설치 ==="
GO_VERSION="1.22.4"
if ! command -v go &>/dev/null || [[ "$(go version)" != *"$GO_VERSION"* ]]; then
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.tar.gz
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    export PATH=$PATH:/usr/local/go/bin
fi
go version

echo "=== [3/5] Go 도구 ==="
go install github.com/cilium/ebpf/cmd/bpf2go@latest
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest
export PATH=$PATH:$(go env GOPATH)/bin

echo "=== [4/5] vmlinux.h ==="
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

echo "=== [5/5] 빌드 ==="
make

echo ""
echo "완료. 실행:"
echo "  master:  ./agentscoped -mode master -listen :9000"
echo "  daemon:  sudo ./agentscoped -mode daemon -master localhost:9000"
