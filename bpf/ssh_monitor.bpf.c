#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "ssh_monitor.h"

char LICENSE[] SEC("license") = "GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, __u32);
    __type(value, __u32);
} sshd_pids SEC(".maps");

const volatile __u16 target_port = 22;

SEC("tp/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (ctx->protocol != IPPROTO_TCP || ctx->newstate != TCP_ESTABLISHED)
        return 0;

    /* We are the server: our sport == target_port */
    if (ctx->sport != target_port)
        return 0;

    struct ssh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = SSH_EVENT_CONNECTION;
    e->pid = pid;
    e->ppid = 0;
    e->source_port = ctx->dport;  /* client's port */
    e->dest_port = ctx->sport;    /* our port (ssh) */
    __builtin_memcpy(e->source_ip4, ctx->daddr, 4);  /* daddr = remote/client IP */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Track this sshd PID for exec/exit correlation */
    __u32 zero = 0;
    bpf_map_update_elem(&sshd_pids, &pid, &zero, BPF_ANY);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    /* Only care if parent is a tracked sshd PID */
    if (!bpf_map_lookup_elem(&sshd_pids, &ppid))
        return 0;

    struct ssh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->event_type = SSH_EVENT_AUTH_SUCCESS;
    e->pid = pid;
    e->ppid = ppid;
    e->source_port = 0;
    e->dest_port = 0;
    __builtin_memset(e->source_ip4, 0, 4);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    if (!bpf_map_lookup_elem(&sshd_pids, &pid))
        return 0;

    struct ssh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->event_type = SSH_EVENT_DISCONNECT;
    e->pid = pid;
    e->ppid = 0;
    e->source_port = 0;
    e->dest_port = 0;
    __builtin_memset(e->source_ip4, 0, 4);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&sshd_pids, &pid);
    return 0;
}
