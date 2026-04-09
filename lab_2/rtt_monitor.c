// SPDX-License-Identifier: GPL
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <linux/tcp.h>

struct event {
    __u64 rtt_ns;
    __u32 pid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("tracepoint/tcp/tcp_rcv_established")
int handle_rtt(struct trace_event_raw_tcp_event_sk *ctx)
{
    struct sock *sk = (struct sock *)ctx->skaddr;
    struct tcp_sock *tp = (struct tcp_sock *)sk;

    __u32 srtt = BPF_CORE_READ(tp, srtt_us);
    if (srtt == 0)
        return 0;

    __u64 rtt_ns = (srtt >> 3) * 1000ULL;

    struct event *e;
    e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->rtt_ns = rtt_ns;
    e->pid = bpf_get_current_pid_tgid() >> 32;

    bpf_ringbuf_submit(e, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
