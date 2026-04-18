package daemon

import (
	"context"
	"log"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "agentscope/gen/agent"
)

type sender struct {
	masterAddr string
	hostname   string // used to rewrite loopback peers so multi-host output is unambiguous
	queue      chan *AgentEvent
}

func newSender(addr, hostname string) *sender {
	return &sender{
		masterAddr: addr,
		hostname:   hostname,
		queue:      make(chan *AgentEvent, 512),
	}
}

func (s *sender) enqueue(e *AgentEvent) { s.queue <- e }

func (s *sender) run() {
	for {
		if err := s.connect(); err != nil {
			log.Printf("master connect failed, retry in 3s: %v", err)
			time.Sleep(3 * time.Second)
		}
	}
}

func (s *sender) connect() error {
	conn, err := grpc.Dial(s.masterAddr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return err
	}
	defer conn.Close()

	client := pb.NewAgentMonitorClient(conn)
	stream, err := client.StreamEvents(context.Background())
	if err != nil {
		return err
	}

	log.Printf("connected to master: %s", s.masterAddr)
	for e := range s.queue {
		// Rewrite loopback peer names *after* parser classification so a
		// call to localhost:11434 on nodeA shows up as "nodeA:11434" in
		// master output, letting operators tell hosts apart. Classifier
		// maps are keyed by the original peer, so this is display-only.
		outPeer := rewriteLoopbackPeer(e.Peer, s.hostname)
		if err := stream.Send(&pb.AgentEvent{
			Host:        e.Host,
			Pid:         e.PID,
			Timestamp:   e.Timestamp,
			Direction:   e.Direction,
			CommType:    e.CommType,
			ContentType: e.ContentType,
			Peer:        outPeer,
			Request:     e.Request,
			Response:    e.Response,
			LatencyMs:   e.LatencyMs,
		}); err != nil {
			log.Printf("send failed, reconnecting: %v", err)
			return err
		}
	}
	return nil
}

// splitHostPort returns (host, ":port") from a peer authority. Handles
// bracketed IPv6 literals correctly — `[::1]:8080` → ("::1", ":8080"),
// `[::1]` → ("::1", ""), `127.0.0.1:11434` → ("127.0.0.1", ":11434").
func splitHostPort(peer string) (host, portSuffix string) {
	if strings.HasPrefix(peer, "[") {
		if end := strings.IndexByte(peer, ']'); end > 0 {
			host = peer[1:end]
			if end+1 < len(peer) && peer[end+1] == ':' {
				portSuffix = peer[end+1:]
			}
			return
		}
	}
	if i := strings.LastIndex(peer, ":"); i > 0 {
		return peer[:i], peer[i:]
	}
	return peer, ""
}

func isLoopback(peer string) bool {
	host, _ := splitHostPort(peer)
	host = strings.ToLower(host)
	switch host {
	case "localhost", "::1", "0:0:0:0:0:0:0:1":
		return true
	}
	return strings.HasPrefix(host, "127.")
}

// rewriteLoopbackPeer replaces a loopback host with the local hostname so
// events from different machines don't collide in the master view. Returns
// the original peer if it's not loopback or the hostname is unknown.
func rewriteLoopbackPeer(peer, hostname string) string {
	if hostname == "" || !isLoopback(peer) {
		return peer
	}
	_, port := splitHostPort(peer)
	return hostname + port
}
