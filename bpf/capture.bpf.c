//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "capture.h"

struct write_arg { __u64 buf; __u32 len; __u64 ssl; };
struct ex_arg { __u64 buf; __u64 num; __u64 written; __u64 ssl; };
struct tcp_recv_arg { __u64 sk; __u64 buf; __u32 buf_len; };

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct write_arg);
} write_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct ex_arg);
} ex_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u64);
    __type(value, struct tcp_recv_arg);
} tcp_recv_args SEC(".maps");

// Per-sock state for the agent-tracked plaintext path:
//   1 = HTTP-confirmed (emit subsequent traffic)
//   2 = TLS handshake observed (skip — handled by SSL_* uprobes)
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, __u64);
    __type(value, __u8);
} tcp_flows SEC(".maps");

// One bit per outbound sock for the discovery path: marks "we already emitted
// a candidate event for this sock". Keeps non-agent processes from drowning
// the ringbuf in repeat metadata. LRU so we don't need a tcp_close hook.
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 16384);
    __type(key, __u64);
    __type(value, __u8);
} candidate_emitted SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

// Userspace populates this dynamically. The detector promotes a PID into
// this map only after observing it talk to a known LLM endpoint; from that
// moment forward the SSL_* uprobes and the "PLAIN" tcp_sendmsg path emit
// full payloads for the PID. The static /proc-scan promotion (env vars,
// cmdline markers) was removed in favor of this discovery-driven model.
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, __u32);
    __type(value, __u8);
} agent_pids SEC(".maps");

static __always_inline int is_agent(void) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    return bpf_map_lookup_elem(&agent_pids, &pid) != NULL;
}

static __always_inline int push_event(u8 dir, u8 source, __u64 buf, u32 len, __u64 conn) {
    if (len == 0) return 0;
    struct capture_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = (u32)id;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->conn = conn;
    e->dst_ip = 0;
    e->dst_port = 0;
    e->dir = dir;
    e->source = source;
    u32 data_len = len < MAX_BUF_SIZE ? len : MAX_BUF_SIZE;
    e->data_len = data_len;
    bpf_probe_read_user(e->data, data_len, (void *)buf);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("uprobe/SSL_write")
int uprobe_ssl_write_entry(struct pt_regs *ctx) {
    if (!is_agent()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    long raw_len = (long)PT_REGS_PARM3(ctx);
    if (raw_len <= 0) return 0;
    struct write_arg arg = {
        .buf = (__u64)PT_REGS_PARM2(ctx),
        .len = (u32)raw_len,
        .ssl = (__u64)PT_REGS_PARM1(ctx),
    };
    bpf_map_update_elem(&write_args, &id, &arg, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write")
int uprobe_ssl_write_ret(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct write_arg *arg = bpf_map_lookup_elem(&write_args, &id);
    if (!arg) return 0;
    push_event(DIR_WRITE, SOURCE_TLS, arg->buf, arg->len, arg->ssl);
    bpf_map_delete_elem(&write_args, &id);
    return 0;
}

SEC("uprobe/SSL_read")
int uprobe_ssl_read_entry(struct pt_regs *ctx) {
    if (!is_agent()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    struct write_arg arg = {
        .buf = (__u64)PT_REGS_PARM2(ctx),
        .len = 0,
        .ssl = (__u64)PT_REGS_PARM1(ctx),
    };
    bpf_map_update_elem(&write_args, &id, &arg, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read")
int uprobe_ssl_read_ret(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct write_arg *arg = bpf_map_lookup_elem(&write_args, &id);
    if (!arg) return 0;
    long ret = (long)PT_REGS_RC(ctx);
    if (ret <= 0) { bpf_map_delete_elem(&write_args, &id); return 0; }
    push_event(DIR_READ, SOURCE_TLS, arg->buf, (u32)ret, arg->ssl);
    bpf_map_delete_elem(&write_args, &id);
    return 0;
}

SEC("uprobe/SSL_write_ex")
int uprobe_ssl_write_ex_entry(struct pt_regs *ctx) {
    if (!is_agent()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    struct ex_arg arg = {
        .buf     = (__u64)PT_REGS_PARM2(ctx),
        .num     = (__u64)PT_REGS_PARM3(ctx),
        .written = (__u64)PT_REGS_PARM4(ctx),
        .ssl     = (__u64)PT_REGS_PARM1(ctx),
    };
    bpf_map_update_elem(&ex_args, &id, &arg, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_write_ex")
int uprobe_ssl_write_ex_ret(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct ex_arg *arg = bpf_map_lookup_elem(&ex_args, &id);
    if (!arg) return 0;
    int ret = (int)PT_REGS_RC(ctx);
    if (ret != 1) { bpf_map_delete_elem(&ex_args, &id); return 0; }
    u64 written = 0;
    bpf_probe_read_user(&written, sizeof(written), (void *)arg->written);
    if (written > 0) push_event(DIR_WRITE, SOURCE_TLS, arg->buf, (u32)written, arg->ssl);
    bpf_map_delete_elem(&ex_args, &id);
    return 0;
}

SEC("uprobe/SSL_read_ex")
int uprobe_ssl_read_ex_entry(struct pt_regs *ctx) {
    if (!is_agent()) return 0;
    u64 id = bpf_get_current_pid_tgid();
    struct ex_arg arg = {
        .buf     = (__u64)PT_REGS_PARM2(ctx),
        .num     = (__u64)PT_REGS_PARM3(ctx),
        .written = (__u64)PT_REGS_PARM4(ctx),
        .ssl     = (__u64)PT_REGS_PARM1(ctx),
    };
    bpf_map_update_elem(&ex_args, &id, &arg, BPF_ANY);
    return 0;
}

SEC("uretprobe/SSL_read_ex")
int uprobe_ssl_read_ex_ret(struct pt_regs *ctx) {
    u64 id = bpf_get_current_pid_tgid();
    struct ex_arg *arg = bpf_map_lookup_elem(&ex_args, &id);
    if (!arg) return 0;
    int ret = (int)PT_REGS_RC(ctx);
    if (ret != 1) { bpf_map_delete_elem(&ex_args, &id); return 0; }
    u64 readbytes = 0;
    bpf_probe_read_user(&readbytes, sizeof(readbytes), (void *)arg->written);
    if (readbytes > 0) push_event(DIR_READ, SOURCE_TLS, arg->buf, (u32)readbytes, arg->ssl);
    bpf_map_delete_elem(&ex_args, &id);
    return 0;
}

// ---------------------------------------------------------------------------
// Plaintext + discovery path (kprobes on tcp_sendmsg / tcp_recvmsg).
//
// Two roles:
//   - PID in agent_pids → full payload capture (SOURCE_PLAIN), TLS sock skip
//   - PID not in agent_pids → one tiny CANDIDATE event per outbound HTTP/TLS
//     socket so userspace can extract SNI / Host and decide whether to
//     promote the PID into agent_pids.
// ---------------------------------------------------------------------------

static __always_inline int read_first_iov(struct msghdr *msg, __u64 *out_buf, __u32 *out_len) {
    struct iov_iter iter;
    __builtin_memset(&iter, 0, sizeof(iter));
    if (bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter) < 0) return -1;

    if (iter.iter_type == ITER_UBUF) {
        *out_buf = (__u64)iter.__ubuf_iovec.iov_base;
        *out_len = (__u32)iter.__ubuf_iovec.iov_len;
        return 0;
    }
    if (iter.iter_type == ITER_IOVEC) {
        const struct iovec *iov = iter.__iov;
        if (!iov) return -1;
        struct iovec first;
        __builtin_memset(&first, 0, sizeof(first));
        if (bpf_probe_read_kernel(&first, sizeof(first), iov) < 0) return -1;
        *out_buf = (__u64)first.iov_base;
        *out_len = (__u32)first.iov_len;
        return 0;
    }
    return -1;
}

static __always_inline int looks_like_http_start(const char h[8]) {
    if (h[0] == 'G' && h[1] == 'E' && h[2] == 'T' && h[3] == ' ') return 1;
    if (h[0] == 'P' && h[1] == 'O' && h[2] == 'S' && h[3] == 'T' && h[4] == ' ') return 1;
    if (h[0] == 'P' && h[1] == 'U' && h[2] == 'T' && h[3] == ' ') return 1;
    if (h[0] == 'H' && h[1] == 'E' && h[2] == 'A' && h[3] == 'D' && h[4] == ' ') return 1;
    if (h[0] == 'D' && h[1] == 'E' && h[2] == 'L' && h[3] == 'E' && h[4] == 'T') return 1;
    if (h[0] == 'P' && h[1] == 'A' && h[2] == 'T' && h[3] == 'C' && h[4] == 'H') return 1;
    if (h[0] == 'O' && h[1] == 'P' && h[2] == 'T' && h[3] == 'I' && h[4] == 'O') return 1;
    if (h[0] == 'C' && h[1] == 'O' && h[2] == 'N' && h[3] == 'N' && h[4] == 'E') return 1;
    if (h[0] == 'H' && h[1] == 'T' && h[2] == 'T' && h[3] == 'P' && h[4] == '/') return 1;
    return 0;
}

// Emits the discovery-mode metadata event. Carries dst IPv4:port plus the
// first <=512 bytes of the first send (enough for SNI in ClientHello and
// for Host: + request line in HTTP). source = SOURCE_CANDIDATE.
static __always_inline void emit_candidate(struct sock *sk, __u64 buf, __u32 len, __u8 hint) {
    struct capture_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return;
    __u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = (__u32)id;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->conn = (__u64)sk;
    __be32 daddr = 0;
    __be16 dport = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    bpf_probe_read_kernel(&dport, sizeof(dport), &sk->__sk_common.skc_dport);
    e->dst_ip = daddr;
    e->dst_port = dport;
    e->dir = hint;
    e->source = SOURCE_CANDIDATE;
    __u32 cap = len < CANDIDATE_PEEK_BYTES ? len : CANDIDATE_PEEK_BYTES;
    e->data_len = cap;
    bpf_probe_read_user(e->data, cap, (void *)buf);
    bpf_ringbuf_submit(e, 0);
}

SEC("kprobe/tcp_sendmsg")
int kprobe_tcp_sendmsg(struct pt_regs *ctx) {
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    if (!sk || !msg) return 0;

    __u64 buf = 0;
    __u32 len = 0;
    if (read_first_iov(msg, &buf, &len) < 0) return 0;
    if (len == 0) return 0;

    __u64 sk_key = (__u64)sk;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (bpf_map_lookup_elem(&agent_pids, &pid)) {
        // ---- agent path: full plaintext capture ----
        __u8 *state = bpf_map_lookup_elem(&tcp_flows, &sk_key);
        if (state) {
            if (*state == 2) return 0; // TLS sock — owned by SSL_* uprobes
        } else {
            char head[8] = {};
            if (bpf_probe_read_user(head, sizeof(head), (void *)buf) < 0) return 0;
            if ((__u8)head[0] == 0x16) {
                __u8 v = 2;
                bpf_map_update_elem(&tcp_flows, &sk_key, &v, BPF_ANY);
                return 0;
            }
            if (!looks_like_http_start(head)) return 0;
            __u8 v = 1;
            bpf_map_update_elem(&tcp_flows, &sk_key, &v, BPF_ANY);
        }
        push_event(DIR_WRITE, SOURCE_PLAIN, buf, len, sk_key);
        return 0;
    }

    // ---- discovery path: one candidate event per outbound sock ----
    if (bpf_map_lookup_elem(&candidate_emitted, &sk_key)) return 0;

    // IPv4 only for MVP. IPv6 LLM traffic still gets full capture once the
    // PID is promoted via a separately-observed IPv4 LLM call — agents
    // typically use both paths.
    __u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &sk->__sk_common.skc_family);
    if (family != 2 /* AF_INET */) return 0;

    __be32 daddr = 0;
    bpf_probe_read_kernel(&daddr, sizeof(daddr), &sk->__sk_common.skc_daddr);
    // 127.0.0.0/8 — task scopes detection to "external traffic".
    if ((bpf_ntohl(daddr) >> 24) == 127) return 0;

    char head[8] = {};
    if (bpf_probe_read_user(head, sizeof(head), (void *)buf) < 0) return 0;
    __u8 hint = 0;
    if ((__u8)head[0] == 0x16) hint = 2;          // TLS ClientHello
    else if (looks_like_http_start(head)) hint = 1; // HTTP request line
    else return 0;

    __u8 v = 1;
    bpf_map_update_elem(&candidate_emitted, &sk_key, &v, BPF_ANY);
    emit_candidate(sk, buf, len, hint);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg_entry(struct pt_regs *ctx) {
    if (!is_agent()) return 0;
    struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
    if (!sk) return 0;

    __u64 sk_key = (__u64)sk;
    __u8 *state = bpf_map_lookup_elem(&tcp_flows, &sk_key);
    if (!state || *state != 1) return 0;

    struct msghdr *msg = (struct msghdr *)PT_REGS_PARM2(ctx);
    if (!msg) return 0;
    __u64 buf = 0;
    __u32 len = 0;
    if (read_first_iov(msg, &buf, &len) < 0) return 0;

    struct tcp_recv_arg arg = { .sk = sk_key, .buf = buf, .buf_len = len };
    __u64 id = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&tcp_recv_args, &id, &arg, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int kprobe_tcp_recvmsg_ret(struct pt_regs *ctx) {
    __u64 id = bpf_get_current_pid_tgid();
    struct tcp_recv_arg *arg = bpf_map_lookup_elem(&tcp_recv_args, &id);
    if (!arg) return 0;
    long ret = (long)PT_REGS_RC(ctx);
    if (ret > 0) {
        __u32 len = (__u32)ret;
        if (len > arg->buf_len && arg->buf_len > 0) len = arg->buf_len;
        push_event(DIR_READ, SOURCE_PLAIN, arg->buf, len, arg->sk);
    }
    bpf_map_delete_elem(&tcp_recv_args, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
