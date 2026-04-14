#ifndef SSH_MONITOR_H
#define SSH_MONITOR_H

enum ssh_event_type {
    SSH_EVENT_CONNECTION = 0,
    SSH_EVENT_AUTH_SUCCESS = 1,
    SSH_EVENT_AUTH_FAILURE = 2,
    SSH_EVENT_DISCONNECT = 3,
};

struct ssh_event {
    __u64 timestamp;
    __u32 event_type;
    __u32 pid;
    __u32 ppid;
    __u32 uid;
    __u16 source_port;
    __u16 dest_port;
    __u8 source_ip4[4];
    __u8 comm[16];
};

#endif
