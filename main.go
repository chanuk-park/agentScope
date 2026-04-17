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
	host := flag.String("host", "", "hostname override (daemon mode, for multi-daemon demo)")
	flag.Parse()

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	switch *mode {
	case "daemon":
		if os.Geteuid() != 0 {
			log.Fatal("daemon은 root 필요 (sudo)")
		}
		daemon.Run(*masterAddr, *host, sig)
	case "master":
		master.Run(*listen, *verbose, sig)
	default:
		log.Fatalf("unknown mode: %s", *mode)
	}
}
