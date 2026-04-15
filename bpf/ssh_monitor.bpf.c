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

/* PID-to-connection correlation map.
 * Tracks which client IP/port belongs to which sshd process.
 * Populated on TCP ESTABLISHED, propagated through sshd fork chain. */
struct conn_info {
    __u8 source_ip4[4];
    __u16 source_port;
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);
    __type(value, struct conn_info);
} conn_map SEC(".maps");

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

    /* Store connection info keyed by PID for later correlation.
     * The PID here may be sshd master or softirq context —
     * the fork handler propagates it to the correct child. */
    {
        __u32 conn_pid = bpf_get_current_pid_tgid() >> 32;
        struct conn_info ci = {};
        __builtin_memcpy(ci.source_ip4, ctx->daddr, 4);
        ci.source_port = ctx->dport;
        bpf_map_update_elem(&conn_map, &conn_pid, &ci, BPF_ANY);
    }

    return 0;
}

/*
 * Fork tracking: when sshd forks, propagate connection info to child.
 * This ensures each sshd child (and its descendants) can be mapped
 * back to the original client connection, fixing IP correlation
 * for concurrent sessions.
 */
SEC("tp/sched/sched_process_fork")
int handle_fork(struct trace_event_raw_sched_process_fork *ctx)
{
    /* In sched_process_fork, the current task is the parent.
     * Use bpf_get_current_comm() — reading __data_loc fields
     * requires variable-offset ctx access which the verifier rejects. */
    char parent_comm[16] = {};
    bpf_get_current_comm(&parent_comm, sizeof(parent_comm));

    if (!is_sshd_comm(parent_comm))
        return 0;

    __u32 parent_pid = ctx->parent_pid;
    __u32 child_pid = ctx->child_pid;

    struct conn_info *info = bpf_map_lookup_elem(&conn_map, &parent_pid);
    if (info) {
        struct conn_info ci;
        __builtin_memcpy(&ci, info, sizeof(ci));
        bpf_map_update_elem(&conn_map, &child_pid, &ci, BPF_ANY);
    }

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

    /* If we ourselves are also sshd, this is sshd's internal forking
       (privilege separation, etc.) — not a user login. The real user
       shell will have a non-sshd comm (bash, zsh, sh, etc.) */
    if (is_sshd_comm(comm))
        return 0;

    /* Skip PAM authentication helpers — they exec under sshd on every
     * password attempt (success or failure), causing false auth_success.
     * unix_chkpwd runs as root to read /etc/shadow regardless of user. */
    if (comm[0] == 'u' && comm[1] == 'n' && comm[2] == 'i' &&
        comm[3] == 'x' && comm[4] == '_')
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
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    /* Look up connection info: try own PID first (fork propagated),
     * then parent PID. */
    {
        struct conn_info *info = bpf_map_lookup_elem(&conn_map, &pid);
        if (!info)
            info = bpf_map_lookup_elem(&conn_map, &ppid);
        if (info) {
            __builtin_memcpy(e->source_ip4, info->source_ip4, 4);
            e->source_port = info->source_port;
            e->dest_port = target_port;
        } else {
            __builtin_memset(e->source_ip4, 0, 4);
            e->source_port = 0;
            e->dest_port = 0;
        }
    }

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
    __builtin_memcpy(e->comm, comm, sizeof(e->comm));

    /* Look up and clean up connection info */
    {
        struct conn_info *info = bpf_map_lookup_elem(&conn_map, &pid);
        if (!info) {
            /* Try parent — sshd privsep monitor might have the entry */
            struct task_struct *task = (struct task_struct *)bpf_get_current_task();
            __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
            info = bpf_map_lookup_elem(&conn_map, &ppid);
        }
        if (info) {
            __builtin_memcpy(e->source_ip4, info->source_ip4, 4);
            e->source_port = info->source_port;
            e->dest_port = target_port;
            bpf_map_delete_elem(&conn_map, &pid);
        } else {
            __builtin_memset(e->source_ip4, 0, 4);
            e->source_port = 0;
            e->dest_port = 0;
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}
