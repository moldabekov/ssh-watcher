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

const volatile __u16 target_port = 22;

/* Helper: check if a comm string starts with "sshd" */
static __always_inline int is_sshd_comm(const char *comm)
{
    return comm[0] == 's' && comm[1] == 's' && comm[2] == 'h' && comm[3] == 'd';
}

/*
 * Connection detection: fires when a TCP socket transitions to ESTABLISHED
 * on our SSH port. Captures client IP/port.
 */
SEC("tp/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx)
{
    if (ctx->protocol != IPPROTO_TCP || ctx->newstate != TCP_ESTABLISHED)
        return 0;
    if (ctx->sport != target_port)
        return 0;

    struct ssh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->event_type = SSH_EVENT_CONNECTION;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = 0;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->source_port = ctx->dport;
    e->dest_port = ctx->sport;
    __builtin_memcpy(e->source_ip4, ctx->daddr, 4);  /* daddr = remote/client IP */
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * Auth success detection: fires on any exec. If the parent process is
 * sshd/sshd-session and the new process is NOT sshd, it means a user
 * shell was spawned — i.e., authentication succeeded.
 */
SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx)
{
    char comm[16] = {};
    char parent_comm[16] = {};

    bpf_get_current_comm(&comm, sizeof(comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    BPF_CORE_READ_STR_INTO(&parent_comm, parent, comm);

    /* Parent must be sshd/sshd-session */
    if (!is_sshd_comm(parent_comm))
        return 0;

    /* If we ourselves are also sshd, this is just sshd forking — skip */
    if (is_sshd_comm(comm))
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    __u32 ppid = BPF_CORE_READ(parent, tgid);

    struct ssh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->event_type = SSH_EVENT_AUTH_SUCCESS;
    e->pid = pid;
    e->ppid = ppid;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->source_port = 0;
    e->dest_port = 0;
    __builtin_memset(e->source_ip4, 0, 4);
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/*
 * Disconnect detection: fires when an sshd-session process exits.
 */
SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx)
{
    char comm[16] = {};
    bpf_get_current_comm(&comm, sizeof(comm));

    /* Only care about sshd process exits */
    if (!is_sshd_comm(comm))
        return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    struct ssh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->event_type = SSH_EVENT_DISCONNECT;
    e->pid = pid;
    e->ppid = 0;
    e->uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    e->source_port = 0;
    e->dest_port = 0;
    __builtin_memset(e->source_ip4, 0, 4);
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    bpf_ringbuf_submit(e, 0);
    return 0;
}
