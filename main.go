//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -output-dir internal/daemon Capture bpf/capture.bpf.c -- -I/usr/include/x86_64-linux-gnu -I/usr/include -D__TARGET_ARCH_x86

package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"

	"agentscope/internal/daemon"
	"agentscope/internal/master"
)

func main() {
	mode := flag.String("mode", "daemon", "daemon | master")
	masterAddr := flag.String("master", "localhost:9000", "master gRPC 주소 (daemon mode)")
	listen := flag.String("listen", ":9000", "listen 주소 (master mode)")
	verbose := flag.Bool("v", false, "body 전체 출력")
	host := flag.String("host", "", "hostname override (daemon mode)")
	cmdlineFilter := flag.String("cmdline-filter", "", "only promote PIDs whose cmdline contains this substring")
	configPath := flag.String("config", "./agentscope.yaml", "YAML config path (optional)")
	symbolMap := flag.String("symbol-map", "", "JSON sidecar of {buildID: {SSL_read: offset, ...}} for stripped static-libssl/BoringSSL binaries (daemon mode)")
	var peerPairs []string
	flag.Var(daemon.NewPeerListFlag(&peerPairs), "peer", "peer comm-type override, e.g. -peer '10.0.0.2:8080=Agent↔Agent' (repeatable)")
	flag.Parse()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	switch *mode {
	case "daemon":
		if os.Geteuid() != 0 {
			log.Fatal("daemon은 root 필요 (sudo)")
		}
		overrides, err := daemon.BuildPeerOverrides(*configPath, peerPairs)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		rules, err := daemon.LoadDetectorRules(*configPath)
		if err != nil {
			log.Fatalf("config: %v", err)
		}
		sidecar, err := daemon.LoadStaticOpenSSLSymbolMap(*symbolMap)
		if err != nil {
			log.Fatalf("symbol-map: %v", err)
		}
		daemon.Run(*masterAddr, *host, *cmdlineFilter, overrides, rules, sidecar, sig)
	case "master":
		master.Run(*listen, *verbose, sig)
	default:
		log.Fatalf("unknown mode: %s", *mode)
	}
}
