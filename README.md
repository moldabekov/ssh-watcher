# ssh-watcher

![GitHub Release](https://img.shields.io/github/v/release/moldabekov/ssh-watcher)
[![Release](https://github.com/moldabekov/ssh-watcher/actions/workflows/release.yml/badge.svg?branch=master)](https://github.com/moldabekov/ssh-watcher/actions/workflows/release.yml)
![GitHub License](https://img.shields.io/github/license/moldabekov/ssh-watcher)
![GitHub repo size](https://img.shields.io/github/repo-size/moldabekov/ssh-watcher)

A Linux daemon that monitors incoming SSH connections and alerts you through desktop notifications, log files, and webhooks. Written in Zig with an eBPF-first detection approach.

## Features

- **4 detection backends** with automatic selection:
  - **eBPF** (preferred) – kernel tracepoints, zero sshd configuration, lowest overhead
  - **systemd journal** – parses sshd log entries in real time
  - **log file tailing** – inotify-based watching of `/var/log/secure` or `/var/log/auth.log`
  - **utmp** – polls login session records
- **3 notification sinks**, each in its own thread:
  - **Desktop notifications** via D-Bus with fork+setuid for root-to-user delivery
  - **JSON log file** – one event per line, includes detection backend, `jq`-friendly
  - **Webhooks** – HTTP POST to Slack, Discord, Telegram, or any endpoint with retry
- **Human-readable notification titles** – "SSH: Authentication Successful", "SSH: Connection Disconnected"
- **Layered TOML config** – system-wide defaults + per-user overrides
- **Configurable events** – choose which events to notify on (connection, auth success/failure, disconnect)
- **Configurable urgency** – set notification urgency per event type
- **Notification templates** – customize title and body with `{event_type}`, `{username}`, `{source_ip}`, etc.
- **Systemd integration** – `sd_notify` readiness, `SIGHUP` config reload, `SIGUSR1` status dump

## Download

Pre-built binaries from [GitHub Releases](https://github.com/moldabekov/ssh-watcher/releases):

| Binary | Linking | Runtime deps |
|--------|---------|-------------|
| `ssh-watcher-x86_64-linux-static` | Fully static (musl) | None – runs on any Linux |
| `ssh-watcher-x86_64-linux` | Dynamic (glibc) | libsystemd, libbpf |

## Requirements

### Build

- Zig 0.15.2+
- clang (for BPF compilation)
- libbpf-devel
- systemd-devel (or elogind-dev on musl systems)
- bpftool (for generating `vmlinux.h`, optional – pre-compiled BPF object included)

### Runtime

- Linux kernel 5.8+ with BTF (`/sys/kernel/btf/vmlinux`) for eBPF backend
- systemd for journal backend
- `/var/log/secure` or `/var/log/auth.log` for logfile backend

## Building

```bash
# Generate BTF header (one time, optional – pre-compiled .bpf.o is included)
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# Dev build
zig build

# Run tests
zig build test

# Production build (ReleaseSmall + LTO + strip + UPX)
zig build release

# Fully static musl build (needs musl sysroot with static libs)
zig build release-static -Dmusl-sysroot=/path/to/sysroot
```

## Installation

```bash
# Install binary
sudo cp zig-out/bin/ssh-watcher /usr/bin/

# Install config
sudo mkdir -p /etc/ssh-watcher
sudo cp config/ssh-watcher.toml /etc/ssh-watcher/config.toml

# Install systemd service
sudo cp config/ssh-watcher.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now ssh-watcher
```

## Configuration

System-wide config at `/etc/ssh-watcher/config.toml`, per-user overrides at `~/.config/ssh-watcher/config.toml`.

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
title_template = "SSH: {event_type}"
body_template = "{username}@{source_ip}"

[log]
enabled = false
path = "/var/log/ssh-watcher.log"

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
sudo ssh-watcher
```

### Systemd service

```bash
sudo systemctl start ssh-watcher
sudo systemctl status ssh-watcher

# View logs
sudo journalctl -u ssh-watcher -f

# Reload config
sudo systemctl reload ssh-watcher

# Status dump
sudo kill -USR1 $(pidof ssh-watcher)
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

### Desktop notifications

The daemon runs as root but delivers notifications to user desktop sessions:

1. **Same UID** – D-Bus direct connection (daemon running as user)
2. **Cross UID** – fork + setuid to target user, then D-Bus (daemon running as root)
3. **Fallback** – `notify-send` with privilege drop (only if fork fails)

dbus-broker on modern Fedora/systemd rejects cross-UID D-Bus connections, so the fork+setuid approach is necessary when running as root.

### eBPF backend

Four BPF tracepoints compiled with CO-RE (Compile Once, Run Everywhere):

- `tp/sock/inet_sock_set_state` – TCP connection established on SSH port
- `tp/sched/sched_process_fork` – sshd fork chain tracking for PID-to-connection correlation
- `tp/sched/sched_process_exec` – user shell spawned under sshd (auth success)
- `tp/sched/sched_process_exit` – sshd session process exit (disconnect)

A BPF LRU hash map (`conn_map`) propagates client IP/port through sshd's fork chain, enabling accurate per-session correlation even with concurrent connections.

The BPF ELF object is embedded in the binary via `@embedFile` – no external file needed at runtime.

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
{"timestamp":1776193237140040708,"event_type":"auth_success","source_ip":"192.168.88.18","source_port":55406,"username":"moldabekov","pid":3842338,"session_id":3842338,"backend":"journal"}
```

Parse with `jq`:

```bash
# All auth failures
cat /var/log/ssh-watcher.log | jq 'select(.event_type == "auth_failure")'

# Unique source IPs
cat /var/log/ssh-watcher.log | jq -r '.source_ip' | sort -u

# Events from a specific IP
cat /var/log/ssh-watcher.log | jq 'select(.source_ip == "10.0.0.1")'

# Events by backend
cat /var/log/ssh-watcher.log | jq 'select(.backend == "ebpf")'
```

## Project structure

```
ssh-watcher/
├── build.zig                  # Build script (dev, release, release-static)
├── .github/workflows/
│   └── release.yml            # CI: static (Alpine/musl) + dynamic (Ubuntu/glibc)
├── bpf/
│   ├── ssh_monitor.bpf.c     # BPF tracepoints (C)
│   ├── ssh_monitor.h          # Shared event struct
│   └── vmlinux.h              # Generated kernel BTF header (gitignored)
├── src/
│   ├── main.zig               # Entry point, signal handling, main loop
│   ├── event.zig              # SSHEvent struct, Backend enum
│   ├── ring_buffer.zig        # Broadcast ring buffer (lock-free, atomic)
│   ├── config.zig             # TOML parser, layered config
│   ├── template.zig           # Notification templates with display names
│   ├── session.zig            # Session correlation table
│   ├── dbus.zig               # Minimal D-Bus wire protocol client
│   ├── detect/
│   │   ├── backend.zig        # Backend interface and probing
│   │   ├── ebpf.zig           # eBPF backend (libbpf)
│   │   ├── journal.zig        # systemd journal backend
│   │   ├── logfile.zig        # Log file tailing backend
│   │   ├── utmp.zig           # utmp polling backend (native struct)
│   │   └── patterns.zig       # sshd log pattern matcher
│   └── notify/
│       ├── sink.zig           # Sink interface
│       ├── desktop.zig        # Desktop notifications (D-Bus + fork+setuid)
│       ├── logwriter.zig      # JSON log writer
│       └── webhook.zig        # Webhook POST with retry
└── config/
    ├── ssh-watcher.toml      # Example config
    └── ssh-watcher.service   # Systemd unit
```

## License

MIT
