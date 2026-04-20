//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -output-dir . SslTrace ../../bpf/ssl_trace.bpf.c -- -I/usr/include/x86_64-linux-gnu -I/usr/include -D__TARGET_ARCH_x86

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
	SSL         uint64
	Type        uint8
	Data        []byte
}

func Run(masterAddr, hostOverride, cmdlineFilter string, configPeers map[string]string, stop chan os.Signal) {
	objs := SslTraceObjects{}
	if err := LoadSslTraceObjects(&objs, nil); err != nil {
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
	parser.emit = sender.enqueue
	go sender.run()

	scannerStop := make(chan struct{})
	scanner := newPIDScanner(objs.AgentPids, parser, 200*time.Millisecond, cmdlineFilter)
	go scanner.run(scannerStop)
	if cmdlineFilter != "" {
		log.Printf("agent filter active (scanning /proc every 200ms, cmdline must contain %q)", cmdlineFilter)
	} else {
		log.Printf("agent filter active (scanning /proc every 200ms)")
	}

	go func() { <-stop; close(scannerStop); rd.Close() }()

	log.Println("capturing... (Ctrl+C to stop)")
	for {
		rec, err := rd.Read()
		if err != nil {
			break
		}
		raw := parseRawEvent(rec.RawSample)
		if isNoiseEvent(raw.Data) {
			continue
		}
		if event := parser.feed(raw); event != nil {
			sender.enqueue(event)
		}
	}
}

func parseRawEvent(b []byte) RawEvent {
	// ssl_event layout: pid(4) tid(4) ts(8) ssl(8) type(1) pad(3) data_len(4) data(N)
	e := RawEvent{
		PID:         binary.LittleEndian.Uint32(b[0:4]),
		TID:         binary.LittleEndian.Uint32(b[4:8]),
		TimestampNs: binary.LittleEndian.Uint64(b[8:16]),
		SSL:         binary.LittleEndian.Uint64(b[16:24]),
		Type:        b[24],
	}
	dataLen := binary.LittleEndian.Uint32(b[28:32])
	if int(dataLen) > len(b)-32 {
		dataLen = uint32(len(b) - 32)
	}
	e.Data = make([]byte, dataLen)
	copy(e.Data, b[32:32+dataLen])
	return e
}

// isNoiseEvent returns true for events whose payload is overwhelmingly zero —
// these appear when bpf_probe_read_user fails or the userspace buffer
// hadn't been written to yet. They don't correspond to real SSL traffic.
// Small frames (HTTP/2 empty DATA/PING/WINDOW) can legitimately be mostly
// zero, so only large events are filtered by the density check.
func isNoiseEvent(b []byte) bool {
	if len(b) == 0 {
		return true
	}
	// Fast path: small events never filtered — HTTP/2 minimal frames are 9 bytes.
	if len(b) < 64 {
		return false
	}
	nonZero := 0
	threshold := len(b) / 32 // require at least ~3% non-zero bytes
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
