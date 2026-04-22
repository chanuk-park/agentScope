//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -output-dir . Capture ../../bpf/capture.bpf.c -- -I/usr/include/x86_64-linux-gnu -I/usr/include -D__TARGET_ARCH_x86

package daemon

import (
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
)

type RawEvent struct {
	PID         uint32
	TID         uint32
	TimestampNs uint64
	Conn        uint64 // SSL* (TLS) or struct sock* (PLAIN/CANDIDATE) — pair with Source
	DstIP       uint32 // BE; meaningful only for SOURCE_CANDIDATE
	DstPort     uint16 // BE; meaningful only for SOURCE_CANDIDATE
	Dir         uint8  // DIR_WRITE/READ for TLS+PLAIN; protocol hint (1=HTTP, 2=TLS) for CANDIDATE
	Source      uint8  // 0=TLS, 1=PLAIN, 2=CANDIDATE
	Data        []byte
}

const sourceCandidate uint8 = 2

func Run(masterAddr, hostOverride, cmdlineFilter string, configPeers map[string]string, rules *DetectorRules, stop chan os.Signal) {
	objs := CaptureObjects{}
	if err := LoadCaptureObjects(&objs, nil); err != nil {
		log.Fatalf("load bpf: %v", err)
	}
	defer objs.Close()

	sslPath, err := findLibSSL()
	if err != nil {
		log.Fatalf("libssl not found: %v", err)
	}
	log.Printf("attaching to %s", sslPath)

	ex, err := link.OpenExecutable(sslPath)
	if err != nil {
		log.Fatalf("open executable: %v", err)
	}

	attach := []struct {
		sym  string
		prog *ebpf.Program
		ret  bool
	}{
		{"SSL_write", objs.UprobeSslWriteEntry, false},
		{"SSL_write", objs.UprobeSslWriteRet, true},
		{"SSL_read", objs.UprobeSslReadEntry, false},
		{"SSL_read", objs.UprobeSslReadRet, true},
		{"SSL_write_ex", objs.UprobeSslWriteExEntry, false},
		{"SSL_write_ex", objs.UprobeSslWriteExRet, true},
		{"SSL_read_ex", objs.UprobeSslReadExEntry, false},
		{"SSL_read_ex", objs.UprobeSslReadExRet, true},
	}

	var links []link.Link
	for _, a := range attach {
		var l link.Link
		if a.ret {
			l, err = ex.Uretprobe(a.sym, a.prog, nil)
		} else {
			l, err = ex.Uprobe(a.sym, a.prog, nil)
		}
		if err != nil {
			log.Fatalf("attach %s: %v", a.sym, err)
		}
		links = append(links, l)
	}

	kprobes := []struct {
		sym  string
		prog *ebpf.Program
		ret  bool
	}{
		{"tcp_sendmsg", objs.KprobeTcpSendmsg, false},
		{"tcp_recvmsg", objs.KprobeTcpRecvmsgEntry, false},
		{"tcp_recvmsg", objs.KprobeTcpRecvmsgRet, true},
	}
	for _, k := range kprobes {
		var l link.Link
		if k.ret {
			l, err = link.Kretprobe(k.sym, k.prog, nil)
		} else {
			l, err = link.Kprobe(k.sym, k.prog, nil)
		}
		if err != nil {
			log.Fatalf("attach kprobe %s: %v", k.sym, err)
		}
		links = append(links, l)
	}
	log.Printf("plaintext capture: tcp_sendmsg + tcp_recvmsg kprobes attached")

	defer func() {
		for _, l := range links {
			l.Close()
		}
	}()

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	hostname := hostOverride
	if hostname == "" {
		hostname, _ = os.Hostname()
	}
	parser := newParser(hostname, configPeers)
	sender := newSender(masterAddr, hostname)
	go sender.run()

	det := newDetector(rules, objs.AgentPids, parser, cmdlineFilter, 5*time.Minute)
	forward := func(ev *AgentEvent) {
		det.observeEvent(ev)
		sender.enqueue(ev)
	}
	parser.emit = forward
	detStop := make(chan struct{})
	go det.runJanitor(detStop)
	if cmdlineFilter != "" {
		log.Printf("detector active (cmdline scope: %q, %d hostnames + %d patterns + %d http paths)",
			cmdlineFilter, len(rules.Hostnames), len(rules.HostnamePatterns), len(rules.HTTPPaths))
	} else {
		log.Printf("detector active (%d hostnames + %d patterns + %d http paths)",
			len(rules.Hostnames), len(rules.HostnamePatterns), len(rules.HTTPPaths))
	}

	go func() { <-stop; close(detStop); rd.Close() }()

	log.Println("capturing... (Ctrl+C to stop)")
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		raw := parseRawEvent(rec.RawSample)
		if raw.Source == sourceCandidate {
			det.handle(raw)
			continue
		}
		if isNoiseEvent(raw.Data) {
			continue
		}
		if event := parser.feed(raw); event != nil {
			forward(event)
		}
	}
}

// parseRawEvent layout matches struct capture_event in bpf/capture.h.
func parseRawEvent(b []byte) RawEvent {
	e := RawEvent{
		PID:         binary.LittleEndian.Uint32(b[0:4]),
		TID:         binary.LittleEndian.Uint32(b[4:8]),
		TimestampNs: binary.LittleEndian.Uint64(b[8:16]),
		Conn:        binary.LittleEndian.Uint64(b[16:24]),
		DstIP:       binary.LittleEndian.Uint32(b[24:28]),
		DstPort:     binary.LittleEndian.Uint16(b[28:30]),
		Dir:         b[30],
		Source:      b[31],
	}
	dataLen := binary.LittleEndian.Uint32(b[32:36])
	if int(dataLen) > len(b)-36 {
		dataLen = uint32(len(b) - 36)
	}
	e.Data = make([]byte, dataLen)
	copy(e.Data, b[36:36+dataLen])
	return e
}

// isNoiseEvent drops mostly-zero payloads (failed bpf_probe_read_user reads). Skips small HTTP/2 control frames.
func isNoiseEvent(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	if len(b) < 64 {
		return false
	}
	nonZero := 0
	threshold := len(b) / 32
	if threshold < 8 {
		threshold = 8
	}
	for _, c := range b {
		if c != 0 {
			nonZero++
			if nonZero >= threshold {
				return false
			}
		}
	}
	return true
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func truncForLog(b []byte) []byte {
	if len(b) > 80 {
		return b[:80]
	}
	return b
}

func tailForLog(b []byte) []byte {
	if len(b) > 40 {
		return b[len(b)-40:]
	}
	return b
}

func findLibSSL() (string, error) {
	patterns := []string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.*",
		"/usr/lib/libssl.so.*",
		"/lib/x86_64-linux-gnu/libssl.so.*",
	}
	for _, p := range patterns {
		if m, _ := filepath.Glob(p); len(m) > 0 {
			return m[0], nil
		}
	}
	return "", fmt.Errorf("libssl.so not found")
}
