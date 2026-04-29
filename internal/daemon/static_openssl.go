package daemon

import (
	"debug/elf"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"os"
)

// staticOpenSSLSymbols holds file offsets of OpenSSL/BoringSSL ABI functions
// inside a binary that statically links libssl (no libssl.so dependency).
// Same C ABI as system libssl, so the existing capture.bpf.c uprobe programs
// (uprobe_ssl_*) attach unchanged — only the *target* changes.
type staticOpenSSLSymbols struct {
	sslWrite   uint64
	sslRead    uint64
	sslWriteEx uint64
	sslReadEx  uint64
}

// staticOpenSSLSymbolMap is a sidecar lookup keyed by ELF BuildID hex string.
// Operators precompute this from unstripped builds and ship it alongside the
// daemon for production use where targets are stripped (Envoy release builds,
// etc.). See LoadStaticOpenSSLSymbolMap.
type staticOpenSSLSymbolMap struct {
	// hex(BuildID) → offsets. nil values are tolerated — entry presence
	// alone confirms a known build, individual offsets may be 0.
	entries map[string]staticOpenSSLSymbols
}

func (m *staticOpenSSLSymbolMap) lookup(buildID string) (*staticOpenSSLSymbols, bool) {
	if m == nil {
		return nil, false
	}
	v, ok := m.entries[buildID]
	if !ok {
		return nil, false
	}
	return &v, true
}

// LoadStaticOpenSSLSymbolMap reads a JSON sidecar file with the shape
//
//	{
//	  "<buildid_hex>": {
//	    "SSL_read":     <file_offset>,
//	    "SSL_write":    <file_offset>,
//	    "SSL_read_ex":  <file_offset>,
//	    "SSL_write_ex": <file_offset>
//	  },
//	  ...
//	}
//
// Daemon falls back to this when a binary's own .symtab/.dynsym don't expose
// SSL_*. Returns nil map (not error) when path is empty.
func LoadStaticOpenSSLSymbolMap(path string) (*staticOpenSSLSymbolMap, error) {
	if path == "" {
		return nil, nil
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	var raw map[string]map[string]uint64
	if err := json.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	m := &staticOpenSSLSymbolMap{entries: map[string]staticOpenSSLSymbols{}}
	for build, syms := range raw {
		m.entries[build] = staticOpenSSLSymbols{
			sslRead:    syms["SSL_read"],
			sslWrite:   syms["SSL_write"],
			sslReadEx:  syms["SSL_read_ex"],
			sslWriteEx: syms["SSL_write_ex"],
		}
	}
	log.Printf("staticssl: loaded %d entries from sidecar %s", len(m.entries), path)
	return m, nil
}

// elfBuildID extracts the GNU build-ID note from an ELF file. Returns ""
// (no error) when the binary doesn't have one — uncommon in practice since
// most distro toolchains emit it by default.
func elfBuildID(f *elf.File) string {
	sec := f.Section(".note.gnu.build-id")
	if sec == nil {
		return ""
	}
	data, err := sec.Data()
	if err != nil || len(data) < 16 {
		return ""
	}
	// Note layout: namesz(4) descsz(4) type(4) name("GNU\0") desc(buildid bytes).
	// Skip 12-byte header + 4-byte aligned name "GNU\0".
	return hex.EncodeToString(data[16:])
}

// resolveStaticOpenSSL inspects path's ELF for statically-linked OpenSSL or
// BoringSSL SSL_* symbols. Returns (nil, nil) when the binary doesn't expose
// SSL_read/SSL_write (most binaries — non-libssl users, fully stripped binaries
// without sidecar, or dynamic-libssl users where the symbols live in libssl.so).
//
// Resolution order:
//  1. Binary's .symtab — exact, present on most non-stripped or --strip-debug builds
//  2. Binary's .dynsym — for `-rdynamic`/exported builds
//  3. Sidecar map (when provided) keyed by ELF BuildID — covers --strip-all
func resolveStaticOpenSSL(path string, sidecar *staticOpenSSLSymbolMap) (*staticOpenSSLSymbols, error) {
	f, err := elf.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open elf: %w", err)
	}
	defer f.Close()

	out := &staticOpenSSLSymbols{}
	collect := func(s elf.Symbol) {
		if elf.ST_TYPE(s.Info) != elf.STT_FUNC {
			return
		}
		off, ok := vaToFileOffset(f, s.Value)
		if !ok {
			return
		}
		switch s.Name {
		case "SSL_read":
			out.sslRead = off
		case "SSL_write":
			out.sslWrite = off
		case "SSL_read_ex":
			out.sslReadEx = off
		case "SSL_write_ex":
			out.sslWriteEx = off
		}
	}
	if syms, err := f.Symbols(); err == nil {
		for _, s := range syms {
			collect(s)
		}
	}
	if syms, err := f.DynamicSymbols(); err == nil {
		for _, s := range syms {
			collect(s)
		}
	}

	if out.sslRead != 0 || out.sslWrite != 0 || out.sslReadEx != 0 || out.sslWriteEx != 0 {
		return out, nil
	}

	// Symbols not in this binary. Try sidecar via BuildID before giving up.
	if sidecar != nil {
		if buildID := elfBuildID(f); buildID != "" {
			if syms, ok := sidecar.lookup(buildID); ok {
				log.Printf("staticssl: %s — symbols from sidecar (BuildID %s)", path, buildID)
				return syms, nil
			}
		}
	}
	return nil, nil
}
