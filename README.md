# ssh-notifier

A Linux daemon that monitors incoming SSH connections and alerts you through desktop notifications, log files, and webhooks. Written in Zig with an eBPF-first detection approach.

## Features

- **4 detection backends** with automatic selection:
  - **eBPF** (preferred) — kernel tracepoints, zero sshd configuration, lowest overhead
  - **systemd journal** — parses sshd log entries in real time
  - **log file tailing** — inotify-based watching of `/var/log/secure` or `/var/log/auth.log`
  - **utmp** — polls login session records
- **3 notification sinks**, each in its own thread:
  - **Desktop notifications** via D-Bus (Wayland/X11) with `notify-send` fallback
  - **JSON log file** — one event per line, `jq`-friendly
  - **Webhooks** — HTTP POST to Slack, Discord, Telegram, or any endpoint with retry
- **Layered TOML config** — system-wide defaults + per-user overrides
- **Configurable events** — choose which events to notify on (connection, auth success/failure, disconnect)
- **Configurable urgency** — set notification urgency per event type
- **Notification templates** — customize title and body with `{event_type}`, `{username}`, `{source_ip}`, etc.
- **Systemd integration** — `sd_notify` readiness, `SIGHUP` config reload, `SIGUSR1` status dump
- **Single static binary** — no runtime dependencies beyond libc, libsystemd, and libbpf

## Requirements

### Build

- Zig 0.15.2+
- clang (for BPF compilation)
- libbpf-devel
- systemd-devel
- bpftool (for generating `vmlinux.h`)

### Runtime

- Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`) for eBPF backend
- systemd for journal backend
- `/var/log/secure` or `/var/log/auth.log` for logfile backend

## Building

```bash
# Generate BTF header (one time)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Build
zig build

# Run tests
zig build test

# Binary is at zig-out/bin/ssh-notifier
```

## Installation

```bash
# Install binary
sudo cp zig-out/bin/ssh-notifier /usr/bin/

# Install config
sudo mkdir -p /etc/ssh-notifier
sudo cp config/ssh-notifier.toml /etc/ssh-notifier/config.toml

# Install systemd service
sudo cp config/ssh-notifier.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-notifier
```

## Configuration

System-wide config at `/etc/ssh-notifier/config.toml`, per-user overrides at `~/.config/ssh-notifier/config.toml`.

```toml
[detection]
backend = "auto"            # "auto", "ebpf", "journal", "logfile", "utmp"
ssh_port = 22
auth_timeout_seconds = 30   # for logfile/journal auth_failure inference

[events]
notify_on_connection = false
notify_on_auth_success = true
notify_on_auth_failure = true
notify_on_disconnect = false

[desktop]
enabled = true
urgency_connection = "low"       # "low", "normal", "critical"
urgency_success = "normal"
urgency_failure = "critical"
urgency_disconnect = "low"
title_template = "SSH {event_type}"
body_template = "{username}@{source_ip}:{source_port}"

[log]
enabled = false
path = "/var/log/ssh-notifier.log"

[webhook]
enabled = false

[[webhook.endpoints]]
url = "https://hooks.slack.com/services/..."
timeout_seconds = 5
max_retries = 3
payload_template = '{"text": "SSH {event_type}: {username} from {source_ip}"}'
```

### Template variables

`{event_type}`, `{username}`, `{source_ip}`, `{source_port}`, `{timestamp}`, `{session_id}`, `{pid}`

### Backend selection

In `auto` mode, the daemon probes backends in priority order and selects the best available:

| Priority | Backend | Requirements |
|----------|---------|-------------|
| 1 | eBPF | Kernel 5.8+, BTF, `CAP_BPF` |
| 2 | journal | systemd |
| 3 | logfile | `/var/log/secure` or `/var/log/auth.log` |
| 4 | utmp | Always available (login events only) |

## Usage

### Run directly

```bash
sudo ssh-notifier
```

### Systemd service

```bash
sudo systemctl start ssh-notifier
sudo systemctl status ssh-notifier

# View logs
sudo journalctl -u ssh-notifier -f

# Reload config
sudo systemctl reload ssh-notifier

# Status dump
sudo kill -USR1 $(pidof ssh-notifier)
```

### Signals

| Signal | Action |
|--------|--------|
| `SIGHUP` | Reload configuration |
| `SIGUSR1` | Dump status to stderr (backend, ring buffer, sessions) |
| `SIGTERM` / `SIGINT` | Graceful shutdown |

## Architecture

```
Detection thread ──writes──> Ring Buffer ──reads──> Desktop sink thread
                                         ──reads──> Log sink thread
                                         ──reads──> Webhook sink thread
```

Single-binary monolith. One detection backend writes `SSHEvent` structs into a broadcast ring buffer (1024 slots). Each notification sink runs in its own thread with an independent consumer cursor. A slow webhook never blocks desktop notifications.

### eBPF backend

Three BPF tracepoints compiled with CO-RE (Compile Once, Run Everywhere):

- `tp/sock/inet_sock_set_state` — TCP connection established on SSH port
- `tp/sched/sched_process_exec` — user shell spawned under sshd (auth success)
- `tp/sched/sched_process_exit` — sshd session process exit (disconnect)

The BPF ELF object is embedded in the binary via `@embedFile` — no external file needed at runtime.

### Journal / logfile backends

Parse sshd log messages with pattern matching:

- `Accepted password for <user> from <ip> port <port>`
- `Accepted publickey for <user> from <ip> port <port>`
- `Failed password for [invalid user] <user> from <ip> port <port>`
- `Disconnected from user <user> <ip> port <port>`
- `Connection closed by [authenticating user <user>] <ip> port <port>`
- `Connection reset by <ip> port <port>`

For journal/logfile backends, connections with no auth event within `auth_timeout_seconds` are inferred as `auth_failure`.

## JSON log format

Each line is a JSON object:

```json
{"timestamp":1776167694632712037,"event_type":"auth_success","source_ip":"192.168.88.20","source_port":53618,"username":"moldabekov","pid":878270,"session_id":878270}
```

Parse with `jq`:

```bash
# All auth failures
cat /var/log/ssh-notifier.log | jq 'select(.event_type == "auth_failure")'

# Unique source IPs
cat /var/log/ssh-notifier.log | jq -r '.source_ip' | sort -u

# Events from a specific IP
cat /var/log/ssh-notifier.log | jq 'select(.source_ip == "10.0.0.1")'
```

## Project structure

```
ssh-notifier/
├── build.zig                  # Build script (BPF + Zig)
├── bpf/
│   ├── ssh_monitor.bpf.c     # BPF tracepoints (C)
│   ├── ssh_monitor.h          # Shared event struct
│   └── vmlinux.h              # Generated kernel BTF header
├── src/
│   ├── main.zig               # Entry point, signal handling, main loop
│   ├── event.zig              # SSHEvent struct
│   ├── ring_buffer.zig        # Broadcast ring buffer
│   ├── config.zig             # TOML parser, layered config
│   ├── template.zig           # Notification templates
│   ├── session.zig            # Session correlation table
│   ├── dbus.zig               # Minimal D-Bus wire protocol
│   ├── detect/
│   │   ├── backend.zig        # Backend interface and probing
│   │   ├── ebpf.zig           # eBPF backend (libbpf)
│   │   ├── journal.zig        # systemd journal backend
│   │   ├── logfile.zig        # Log file tailing backend
│   │   ├── utmp.zig           # utmp polling backend
│   │   └── patterns.zig       # sshd log pattern matcher
│   └── notify/
│       ├── sink.zig           # Sink interface
│       ├── desktop.zig        # Desktop notifications
│       ├── logwriter.zig      # JSON log writer
│       └── webhook.zig        # Webhook POST with retry
└── config/
    ├── ssh-notifier.toml      # Example config
    └── ssh-notifier.service   # Systemd unit
```

## License

TBD
