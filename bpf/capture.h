#pragma once

// Layout shared with internal/daemon/loader.go (parseRawEvent reads by offset).

#define MAX_BUF_SIZE 16384
#define CANDIDATE_PEEK_BYTES 512

enum capture_dir { DIR_WRITE = 0, DIR_READ = 1 };

// CANDIDATE = lightweight observe path for non-tracked PIDs (carries dst + first-bytes for SNI/Host parse).
// GO_TLS = userspace plaintext from Go's crypto/tls.(*Conn).Read/Write uprobes (Go register ABI, not C).
enum capture_source { SOURCE_TLS = 0, SOURCE_PLAIN = 1, SOURCE_CANDIDATE = 2, SOURCE_GO_TLS = 3 };

struct capture_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp_ns;
    __u64 conn;             // SSL* (TLS) or struct sock* (PLAIN/CANDIDATE)
    __u32 dst_ip;           // BE; meaningful only for CANDIDATE
    __u16 dst_port;         // BE; meaningful only for CANDIDATE
    __u8  dir;              // capture_dir for TLS+PLAIN; protocol hint (1=HTTP, 2=TLS) for CANDIDATE
    __u8  source;
    __u32 data_len;
    char  data[MAX_BUF_SIZE];
};
