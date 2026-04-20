package master

import (
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"

	pb "agentscope/gen/agent"
)

type monitorServer struct {
	pb.UnimplementedAgentMonitorServer
	printer  *printer
	hostMu   sync.RWMutex
	hostByIP map[string]string // daemon source IP → -host value
}

// learnDaemonIP records that the daemon at `ip` identifies itself as `host`.
// Called on every event; idempotent so it tolerates re-connects.
func (s *monitorServer) learnDaemonIP(ip, host string) {
	if ip == "" || host == "" {
		return
	}
	s.hostMu.RLock()
	existing, ok := s.hostByIP[ip]
	s.hostMu.RUnlock()
	if ok && existing == host {
		return
	}
	s.hostMu.Lock()
	s.hostByIP[ip] = host
	s.hostMu.Unlock()
}

// rewritePeer replaces a bare-IP peer (like "10.10.10.173:8448") with the
// hostname of the daemon running on that IP, when one is registered.
// Leaves loopback / already-hostname peers untouched.
func (s *monitorServer) rewritePeer(p string) string {
	host := p
	port := ""
	if i := strings.LastIndexByte(p, ':'); i >= 0 {
		host, port = p[:i], p[i:]
	}
	// Only rewrite bare IPv4 / IPv6 addresses.
	if !looksLikeIP(host) {
		return p
	}
	s.hostMu.RLock()
	hn, ok := s.hostByIP[host]
	s.hostMu.RUnlock()
	if !ok {
		return p
	}
	return hn + port
}

func looksLikeIP(h string) bool {
	return net.ParseIP(h) != nil
}

func (s *monitorServer) StreamEvents(stream pb.AgentMonitor_StreamEventsServer) error {
	// The gRPC peer gives us the daemon's source TCP address; the first
	// event's Host field tells us what the daemon calls itself. Pair them
	// so subsequent events from other daemons can render this daemon's IP
	// as its hostname when it shows up as a peer (cross-host A2A/MCP).
	srcIP := ""
	if p, ok := peer.FromContext(stream.Context()); ok && p.Addr != nil {
		addr := p.Addr.String()
		if i := strings.LastIndexByte(addr, ':'); i >= 0 {
			srcIP = addr[:i]
		}
	}

	// Eagerly register IP→host from stream-open metadata. Daemons attach
	// `x-agentscope-host` before sending any events; registering here closes
	// the race where another daemon's first A2A event arrives first and
	// would otherwise render with a bare-IP peer.
	if md, ok := metadata.FromIncomingContext(stream.Context()); ok {
		if v := md.Get("x-agentscope-host"); len(v) > 0 {
			s.learnDaemonIP(srcIP, v[0])
		}
	}

	for {
		e, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.Ack{})
		}
		if err != nil {
			return err
		}

		s.learnDaemonIP(srcIP, e.Host)

		s.printer.print(&Event{
			Host:        e.Host,
			PID:         uint32(e.Pid),
			Timestamp:   e.Timestamp,
			Direction:   e.Direction,
			CommType:    e.CommType,
			ContentType: e.ContentType,
			Peer:        s.rewritePeer(e.Peer),
			Request:     e.Request,
			Response:    e.Response,
			LatencyMs:   e.LatencyMs,
		})
	}
}

func Run(listenAddr string, verbose bool, stop chan os.Signal) {
	lis, err := net.Listen("tcp", listenAddr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	srv := grpc.NewServer()
	pb.RegisterAgentMonitorServer(srv, &monitorServer{
		printer:  newPrinter(verbose),
		hostByIP: make(map[string]string),
	})

	log.Printf("master listening on %s", listenAddr)
	go func() { <-stop; srv.GracefulStop() }()
	srv.Serve(lis)
}
