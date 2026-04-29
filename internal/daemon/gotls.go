package daemon

import (
	"bytes"
	"debug/elf"
	"debug/gosym"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/arch/x86/x86asm"
)

// goTLSSymbols holds file offsets + sizes of crypto/tls.(*Conn).Read and Write
// inside a Go binary. Sizes are needed to disassemble for RET-instruction scan
// (uretprobes corrupt Go's stack — see goTLSAttacher.attachBinary).
type goTLSSymbols struct {
	readEntry  uint64
	readSize   uint64
	writeEntry uint64
	writeSize  uint64
}

// resolveGoTLS inspects path and returns (offsets, nil) when path is a Go
// binary that statically links crypto/tls. Returns (nil, nil) for non-Go
// or no-crypto/tls. Returns (nil, err) on real I/O errors.
func resolveGoTLS(path string) (*goTLSSymbols, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open elf: %w", err)
	}
	defer f.Close()

	pcln := f.Section(".gopclntab")
	if pcln == nil {
		return nil, nil
	}

	out := &goTLSSymbols{}

	if syms, symErr := f.Symbols(); symErr == nil {
		for _, s := range syms {
			switch s.Name {
			case "crypto/tls.(*Conn).Read":
				if off, ok := vaToFileOffset(f, s.Value); ok {
					out.readEntry = off
					out.readSize = s.Size
				}
			case "crypto/tls.(*Conn).Write":
				if off, ok := vaToFileOffset(f, s.Value); ok {
					out.writeEntry = off
					out.writeSize = s.Size
				}
			}
		}
		if out.readEntry != 0 && out.writeEntry != 0 && out.readSize != 0 && out.writeSize != 0 {
			return out, nil
		}
	}

	// PCLN fallback — works on stripped binaries.
	pclnData, err := pcln.Data()
	if err != nil {
		return nil, fmt.Errorf("read .gopclntab: %w", err)
	}
	text := f.Section(".text")
	if text == nil {
		return nil, fmt.Errorf("no .text section")
	}
	lt := gosym.NewLineTable(pclnData, text.Addr)
	tab, err := gosym.NewTable(nil, lt)
	if err != nil {
		return nil, fmt.Errorf("parse pcln: %w", err)
	}
	if fn := tab.LookupFunc("crypto/tls.(*Conn).Read"); fn != nil && (out.readEntry == 0 || out.readSize == 0) {
		if off, ok := vaToFileOffset(f, fn.Entry); ok {
			out.readEntry = off
			out.readSize = fn.End - fn.Entry
		}
	}
	if fn := tab.LookupFunc("crypto/tls.(*Conn).Write"); fn != nil && (out.writeEntry == 0 || out.writeSize == 0) {
		if off, ok := vaToFileOffset(f, fn.Entry); ok {
			out.writeEntry = off
			out.writeSize = fn.End - fn.Entry
		}
	}
	if out.readEntry == 0 || out.writeEntry == 0 || out.readSize == 0 || out.writeSize == 0 {
		return nil, nil
	}
	return out, nil
}

// vaToFileOffset converts a virtual address to a file offset using PT_LOAD
// program headers.
func vaToFileOffset(f *elf.File, va uint64) (uint64, bool) {
	for _, p := range f.Progs {
		if p.Type != elf.PT_LOAD {
			continue
		}
		if va >= p.Vaddr && va < p.Vaddr+p.Filesz {
			return va - p.Vaddr + p.Off, true
		}
	}
	return 0, false
}

// findRetOffsets disassembles the function body at funcOffset..funcOffset+size
// and returns file offsets of every RET instruction. We attach uprobes (not
// uretprobes) at these offsets because Go's runtime panics with "unexpected
// return pc" when a uretprobe rewrites the on-stack return address.
func findRetOffsets(path string, funcOffset, size uint64) ([]uint64, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	buf := make([]byte, size)
	if _, err := f.ReadAt(buf, int64(funcOffset)); err != nil {
		return nil, fmt.Errorf("read function body: %w", err)
	}
	var rets []uint64
	pos := 0
	for pos < len(buf) {
		inst, err := x86asm.Decode(buf[pos:], 64)
		if err != nil {
			pos++
			continue
		}
		if inst.Op == x86asm.RET {
			rets = append(rets, funcOffset+uint64(pos))
		}
		if inst.Len <= 0 {
			pos++
			continue
		}
		pos += inst.Len
	}
	return rets, nil
}

// goTLSAttacher manages Go TLS uprobe attachments. It is responsible for:
//  1. Initial scan at daemon startup (attaches to Go binaries already running
//     and matching the cmdline filter).
//  2. Dynamic attach on detector promote — when a Go binary is observed for
//     the first time, attach uprobes immediately so the next Read/Write call
//     captures plaintext.
//
// Attachment is per-binary (not per-PID): once a binary is attached, every PID
// running the same binary triggers the uprobe. The BPF is_agent() filter then
// restricts capture to PIDs in agent_pids.
type goTLSAttacher struct {
	objs    *CaptureObjects
	sidecar *staticOpenSSLSymbolMap // nil if no symbol-map flag given

	mu sync.Mutex
	// attached: canonical exe path → links attached for that binary.
	// nil value means "claim in flight or empty result" — short-circuits parallel
	// attachByPID for the same exe. GC walks /proc to evict dead-binary entries.
	attached map[string][]link.Link
}

func newGoTLSAttacher(objs *CaptureObjects, sidecar *staticOpenSSLSymbolMap) *goTLSAttacher {
	return &goTLSAttacher{
		objs:     objs,
		sidecar:  sidecar,
		attached: map[string][]link.Link{},
	}
}

// initialScan walks /proc, finds Go binaries whose cmdline contains filter,
// and attaches uprobes to each. Called once at daemon startup. Returns total
// number of (binary × probe) attachments.
func (a *goTLSAttacher) initialScan(cmdlineFilter string) int {
	if cmdlineFilter == "" {
		return 0
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0
	}
	filterB := []byte(cmdlineFilter)
	total := 0
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		cmdline, err := os.ReadFile("/proc/" + e.Name() + "/cmdline")
		if err != nil || !bytes.Contains(cmdline, filterB) {
			continue
		}
		exe, err := filepath.EvalSymlinks("/proc/" + e.Name() + "/exe")
		if err != nil {
			continue
		}
		total += a.attachBinary(exe, "startup")
	}
	return total
}

// attachByPID is the detector callback. Resolves /proc/PID/exe and attaches
// uprobes if it's a Go binary not yet seen.
func (a *goTLSAttacher) attachByPID(pid uint32) {
	exe, err := filepath.EvalSymlinks(fmt.Sprintf("/proc/%d/exe", pid))
	if err != nil {
		return
	}
	a.attachBinary(exe, fmt.Sprintf("promote pid=%d", pid))
}

// attachBinary is idempotent — checks the seen set, resolves symbols, and
// attaches the three program types (write entry, read entry, read RET fanout).
// Returns the number of probes attached on this call (0 if already attached
// or not Go-with-crypto/tls).
func (a *goTLSAttacher) attachBinary(exe, reason string) int {
	a.mu.Lock()
	if _, ok := a.attached[exe]; ok {
		a.mu.Unlock()
		return 0
	}
	a.attached[exe] = nil // claim slot so parallel calls short-circuit
	a.mu.Unlock()

	ex, err := link.OpenExecutable(exe)
	if err != nil {
		log.Printf("attach: skip %s: open: %v", exe, err)
		return 0
	}

	var newLinks []link.Link
	count := 0
	count += a.attachGoTLS(exe, ex, &newLinks, reason)
	count += a.attachStaticOpenSSL(exe, ex, &newLinks, reason)

	a.mu.Lock()
	a.attached[exe] = newLinks
	a.mu.Unlock()
	return count
}

// attachGoTLS resolves crypto/tls.(*Conn).Read/Write in a Go binary and
// attaches uprobes (with RET-instruction fan-out for the read return path).
// Returns 0 if the binary isn't a Go-with-crypto/tls binary.
func (a *goTLSAttacher) attachGoTLS(exe string, ex *link.Executable, links *[]link.Link, reason string) int {
	syms, err := resolveGoTLS(exe)
	if err != nil {
		log.Printf("gotls: %s: resolve: %v", exe, err)
		return 0
	}
	if syms == nil {
		return 0
	}

	tryAttach := func(label string, off uint64, prog *ebpf.Program) bool {
		l, err := ex.Uprobe("", prog, &link.UprobeOptions{Address: off})
		if err != nil {
			log.Printf("gotls: skip %s:%s@0x%x: %v", exe, label, off, err)
			return false
		}
		*links = append(*links, l)
		return true
	}
	count := 0
	if tryAttach("write", syms.writeEntry, a.objs.UprobeGoTlsWrite) {
		count++
	}
	if tryAttach("read-entry", syms.readEntry, a.objs.UprobeGoTlsReadEntry) {
		count++
	}
	rets, err := findRetOffsets(exe, syms.readEntry, syms.readSize)
	if err != nil {
		log.Printf("gotls: %s: scan RET: %v", exe, err)
	}
	for _, off := range rets {
		if tryAttach("read-ret", off, a.objs.UprobeGoTlsReadRet) {
			count++
		}
	}
	if count > 0 {
		log.Printf("gotls: attached %d probes on %s (%s; write@0x%x, read@0x%x + %d RET)",
			count, exe, reason, syms.writeEntry, syms.readEntry, len(rets))
	}
	return count
}

// attachStaticOpenSSL resolves SSL_* symbols in a binary that statically
// links libssl/BoringSSL, and attaches the existing OpenSSL uprobe programs
// at those file offsets. C ABI (no Go runtime panics) → uretprobes work fine.
func (a *goTLSAttacher) attachStaticOpenSSL(exe string, ex *link.Executable, links *[]link.Link, reason string) int {
	syms, err := resolveStaticOpenSSL(exe, a.sidecar)
	if err != nil {
		log.Printf("staticssl: %s: resolve: %v", exe, err)
		return 0
	}
	if syms == nil {
		return 0
	}

	// (offset, entry-prog, ret-prog, label). entry/ret share the same offset.
	type pair struct {
		off       uint64
		entryProg *ebpf.Program
		retProg   *ebpf.Program
		label     string
	}
	pairs := []pair{
		{syms.sslWrite, a.objs.UprobeSslWriteEntry, a.objs.UprobeSslWriteRet, "SSL_write"},
		{syms.sslRead, a.objs.UprobeSslReadEntry, a.objs.UprobeSslReadRet, "SSL_read"},
		{syms.sslWriteEx, a.objs.UprobeSslWriteExEntry, a.objs.UprobeSslWriteExRet, "SSL_write_ex"},
		{syms.sslReadEx, a.objs.UprobeSslReadExEntry, a.objs.UprobeSslReadExRet, "SSL_read_ex"},
	}
	count := 0
	for _, p := range pairs {
		if p.off == 0 {
			continue // symbol not present (e.g., older OpenSSL without _ex variants)
		}
		if l, err := ex.Uprobe("", p.entryProg, &link.UprobeOptions{Address: p.off}); err == nil {
			*links = append(*links, l)
			count++
		} else {
			log.Printf("staticssl: skip %s:%s entry@0x%x: %v", exe, p.label, p.off, err)
		}
		if l, err := ex.Uretprobe("", p.retProg, &link.UprobeOptions{Address: p.off}); err == nil {
			*links = append(*links, l)
			count++
		} else {
			log.Printf("staticssl: skip %s:%s ret@0x%x: %v", exe, p.label, p.off, err)
		}
	}
	if count > 0 {
		log.Printf("staticssl: attached %d probes on %s (%s; write@0x%x read@0x%x write_ex@0x%x read_ex@0x%x)",
			count, exe, reason, syms.sslWrite, syms.sslRead, syms.sslWriteEx, syms.sslReadEx)
	}
	return count
}

// close releases all attached uprobes. Called from loader's defer.
func (a *goTLSAttacher) close() {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, links := range a.attached {
		for _, l := range links {
			l.Close()
		}
	}
	a.attached = map[string][]link.Link{}
}

// liveExes returns the set of canonical exe paths currently running on the
// host (one /proc walk).
func liveExes() map[string]bool {
	out := map[string]bool{}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return out
	}
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(e.Name()); err != nil {
			continue
		}
		exe, err := filepath.EvalSymlinks("/proc/" + e.Name() + "/exe")
		if err != nil {
			continue
		}
		out[exe] = true
	}
	return out
}

// gc detaches uprobes for binaries that no PID currently runs. Bounds the
// long-term growth of attached/links across many short-lived binaries.
// Re-attach on subsequent promote is the same code path as initial attach.
func (a *goTLSAttacher) gc() {
	live := liveExes()

	a.mu.Lock()
	var (
		toClose [][]link.Link
		dead    []string
	)
	for exe, links := range a.attached {
		if !live[exe] {
			toClose = append(toClose, links)
			dead = append(dead, exe)
		}
	}
	for _, exe := range dead {
		delete(a.attached, exe)
	}
	a.mu.Unlock()

	closed := 0
	for _, links := range toClose {
		for _, l := range links {
			l.Close()
			closed++
		}
	}
	if closed > 0 {
		log.Printf("gotls: GC detached %d uprobes from %d dead binaries (%v)", closed, len(dead), dead)
	}
}

// runGC ticks every interval until stop closes. Intended to run as a goroutine.
func (a *goTLSAttacher) runGC(interval time.Duration, stop <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-stop:
			return
		case <-t.C:
			a.gc()
		}
	}
}
