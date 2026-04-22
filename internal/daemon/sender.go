package daemon

import (
	"context"
	"log"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"

	pb "agentscope/gen/agent"
)

type sender struct {
	masterAddr string
	hostname   string
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
	// Send hostname in stream-open metadata so master registers IP→host before any events arrive.
	ctx := context.Background()
	if s.hostname != "" {
		ctx = metadata.AppendToOutgoingContext(ctx, "x-agentscope-host", s.hostname)
	}
	stream, err := client.StreamEvents(ctx)
	if err != nil {
		return err
	}

	log.Printf("connected to master: %s", s.masterAddr)
	for e := range s.queue {
		// Display-only: rewrite loopback peer to hostname so multi-host master output disambiguates.
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

// splitHostPort handles bracketed IPv6: `[::1]:8080` → ("::1", ":8080").
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

// rewriteLoopbackPeer: loopback host → local hostname (no-op when not loopback or hostname unknown).
func rewriteLoopbackPeer(peer, hostname string) string {
	if hostname == "" || !isLoopback(peer) {
		return peer
	}
	_, port := splitHostPort(peer)
	return hostname + port
}
