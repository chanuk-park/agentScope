#pragma once

// Shared layout between the BPF programs in capture.bpf.c and the Go
// userspace reader in internal/daemon/loader.go (parseRawEvent). The byte
// layout here is load-bearing — Go reads raw ringbuf bytes by offset, so any
// reorder MUST be mirrored on both sides.

#define MAX_BUF_SIZE 16384
#define CANDIDATE_PEEK_BYTES 512

// Direction of a payload capture. Only meaningful for SOURCE_TLS and
// SOURCE_PLAIN events (CANDIDATE events overload the `dir` byte as a
// protocol hint — see capture_source below).
enum capture_dir { DIR_WRITE = 0, DIR_READ = 1 };

// source distinguishes the three capture paths:
//   TLS       — OpenSSL uprobes (SSL_write/read[_ex]), plaintext just
//               before encryption.
//   PLAIN     — tcp_sendmsg/tcp_recvmsg kprobes for already-tracked agents,
//               full payload of outbound plaintext HTTP.
//   CANDIDATE — single lightweight event per new outbound sock from a
//               non-tracked process, carrying just enough bytes for
//               SNI/Host extraction in userspace.
enum capture_source { SOURCE_TLS = 0, SOURCE_PLAIN = 1, SOURCE_CANDIDATE = 2 };

struct capture_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp_ns;
    __u64 conn;             // SSL* (TLS) or struct sock* (PLAIN/CANDIDATE)
    __u32 dst_ip;           // BE IPv4; meaningful for CANDIDATE, 0 elsewhere
    __u16 dst_port;         // BE port;  meaningful for CANDIDATE, 0 elsewhere
    __u8  dir;              // capture_dir for TLS+PLAIN; protocol hint (1=HTTP, 2=TLS) for CANDIDATE
    __u8  source;           // capture_source
    __u32 data_len;
    char  data[MAX_BUF_SIZE];
};
