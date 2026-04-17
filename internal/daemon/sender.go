package daemon

import (
	"context"
	"log"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"

	pb "agentscope/gen/agent"
)

type sender struct {
	masterAddr string
	queue      chan *AgentEvent
}

func newSender(addr string) *sender {
	return &sender{masterAddr: addr, queue: make(chan *AgentEvent, 512)}
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
		if err := stream.Send(&pb.AgentEvent{
			Host:        e.Host,
			Pid:         e.PID,
			Timestamp:   e.Timestamp,
			Direction:   e.Direction,
			CommType:    e.CommType,
			ContentType: e.ContentType,
			Peer:        e.Peer,
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
