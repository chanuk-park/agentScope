package master

import (
	"io"
	"log"
	"net"
	"os"

	"google.golang.org/grpc"

	pb "agentscope/gen/agent"
)

type monitorServer struct {
	pb.UnimplementedAgentMonitorServer
	printer *printer
}

func (s *monitorServer) StreamEvents(stream pb.AgentMonitor_StreamEventsServer) error {
	for {
		e, err := stream.Recv()
		if err == io.EOF {
			return stream.SendAndClose(&pb.Ack{})
		}
		if err != nil {
			return err
		}

		s.printer.print(&Event{
			Host:        e.Host,
			PID:         uint32(e.Pid),
			Timestamp:   e.Timestamp,
			Direction:   e.Direction,
			CommType:    e.CommType,
			ContentType: e.ContentType,
			Peer:        e.Peer,
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
		printer: newPrinter(verbose),
	})

	log.Printf("master listening on %s", listenAddr)
	go func() { <-stop; srv.GracefulStop() }()
	srv.Serve(lis)
}
