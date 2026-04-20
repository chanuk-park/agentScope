#pragma once

#define MAX_BUF_SIZE 16384

enum ssl_event_type { SSL_WRITE = 0, SSL_READ = 1 };

struct ssl_event {
    __u32 pid;
    __u32 tid;
    __u64 timestamp_ns;
    __u64 ssl;              // SSL* pointer — distinguishes concurrent TLS conns on same PID
    __u8  type;
    __u32 data_len;
    char  data[MAX_BUF_SIZE];
};
