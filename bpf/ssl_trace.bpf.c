//go:build ignore

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "ssl_trace.h"

struct write_arg { __u64 buf; __u32 len; __u64 ssl; };
struct ex_arg { __u64 buf; __u64 num; __u64 written; __u64 ssl; };

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
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024 * 1024);
} events SEC(".maps");

// Userspace maintains this map. Only PIDs present here will have their
// SSL traffic captured. Kept empty to mean "no filter" is not an option —
// userspace must always publish at least the self-PID of long-running
// agents before their traffic appears on the wire.
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

static __always_inline int push_event(u8 type, __u64 buf, u32 len, __u64 ssl) {
    if (len == 0) return 0;
    struct ssl_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    u64 id = bpf_get_current_pid_tgid();
    e->pid = id >> 32;
    e->tid = (u32)id;
    e->timestamp_ns = bpf_ktime_get_ns();
    e->ssl = ssl;
    e->type = type;
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
    push_event(SSL_WRITE, arg->buf, arg->len, arg->ssl);
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
    push_event(SSL_READ, arg->buf, (u32)ret, arg->ssl);
    bpf_map_delete_elem(&write_args, &id);
    return 0;
}

// SSL_write_ex(ssl, buf, num, *written) returns 1 on success.
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
    if (written > 0) push_event(SSL_WRITE, arg->buf, (u32)written, arg->ssl);
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
        .written = (__u64)PT_REGS_PARM4(ctx), // *readbytes
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
    if (readbytes > 0) push_event(SSL_READ, arg->buf, (u32)readbytes, arg->ssl);
    bpf_map_delete_elem(&ex_args, &id);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
