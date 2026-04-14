# SSH Notifier — Design Spec

A Zig daemon that monitors incoming SSH connections via multiple detection backends and alerts users through desktop notifications, log files, and webhooks.

## Core Event Model

Every detection backend produces the same event struct:

```zig
const SSHEvent = struct {
    timestamp: u64,            // monotonic nanoseconds
    event_type: EventType,
    source_ip: [16]u8,         // IPv4-mapped-IPv6 or native IPv6
    source_port: u16,
    username: [64]u8,          // PAM username if available
    pid: u32,                  // sshd child PID
    session_id: ?u64,          // links connect/auth/disconnect into one session
};

const EventType = enum {
    connection,
    auth_success,
    auth_failure,
    disconnect,
};
```

- `session_id` ties related events together across their lifecycle.
- The daemon maintains an in-memory session table (max 4096 entries, LRU eviction) to correlate events. Entries also expire after 2x `auth_timeout_seconds` if no new activity is seen.
- Detection backends emit everything. Filtering happens after, based on user config.

## Detection Backends

The daemon probes available backends at startup. In `auto` mode, it activates the highest-priority backend available. Only one primary backend runs at a time (utmp can optionally run as a supplementary source alongside the primary backend if explicitly configured via `backend = "ebpf+utmp"` or similar). Priority order:

### 1. eBPF (preferred)

A BPF program (single C source file with three tracepoint attachments), compiled at build time via `zig cc`, embedded in the binary.

- **`inet_csk_accept` tracepoint** — fires on inbound TCP connections. Filters to the configured SSH port in-kernel. Captures source IP, port, sshd PID. Produces `connection` events.
- **`sched_process_exec` tracepoint** — watches for process exec under sshd parent PIDs. When sshd forks a child that execs a shell, that's a successful login. Produces `auth_success`. A connection event with no corresponding exec within a timeout window (default: 30 seconds, configurable via `detection.auth_timeout_seconds`) is inferred as `auth_failure`.
- **`sched_process_exit` tracepoint** — when the sshd child PID exits, produces `disconnect`.
- Uses CO-RE with BTF for kernel portability (5.8+). Checks for `/sys/kernel/btf/vmlinux` at startup.
- Events delivered to userspace via BPF ring buffer (`BPF_MAP_TYPE_RINGBUF`).

### 2. systemd journal

- Subscribes via `sd_journal` with filter `_SYSTEMD_UNIT=sshd.service`.
- Parses sshd log messages with known patterns ("Accepted password for...", "Failed password for...", "Disconnected from...").
- Activated if systemd is detected (`/run/systemd/system` exists).

### 3. Log file tailing

- Watches `/var/log/auth.log` (Debian/Ubuntu) or `/var/log/secure` (RHEL/Fedora) via `inotify`.
- Same pattern-based parsing as journal backend.
- Activated when neither eBPF nor journal is available.

### 4. utmp/wtmp

- Polls `utmp` for session records.
- Only produces `auth_success` and `disconnect` (no failed attempts).
- Last-resort primary source, or supplementary alongside another backend when explicitly configured.

### Backend selection

Automatic by default, overridable in config:

```toml
[detection]
backend = "auto"  # or "ebpf", "journal", "logfile", "utmp"
ssh_port = 22
```

## Notification Sinks & Threading

Each sink runs in its own dedicated thread, consuming events from a shared ring buffer (default capacity: 1024 events). The detection thread writes events; sink threads read independently at their own pace, each tracking its own read position.

```
Detection thread ──writes──> Ring Buffer ──reads──> Desktop sink thread
                                         ──reads──> Log sink thread
                                         ──reads──> Webhook sink thread
```

If a sink falls behind and the buffer wraps, it skips to the current position and logs a warning.

### Desktop Notifications

- Attempts native D-Bus call to `org.freedesktop.Notifications.Notify` on the user's session bus.
- Discovers active graphical sessions via `sd_login_enumerate_sessions` on systemd systems, or by scanning `/run/user/*/bus` and checking for `DISPLAY`/`WAYLAND_DISPLAY` in `/proc/<pid>/environ` of session leaders on non-systemd systems.
- Sends notifications to all active graphical sessions (multi-user support).
- Falls back to spawning `notify-send` as the target user via `setuid`/`setgid` + `DBUS_SESSION_BUS_ADDRESS`.
- Configurable urgency level per event type and notification templates.

### Log File

- Appends one JSON object per line to a configurable path (default: `/var/log/ssh-notifier.log`).
- Supports log rotation via `SIGHUP` to reopen file handle.

### Webhook

- HTTP POST to one or more configured URLs.
- JSON payload with event fields.
- Retry with exponential backoff (1s, 2s, 4s), max 3 attempts per event.
- Configurable timeout (default 5s).
- Supports payload templates for Slack/Discord/Telegram/generic formatting.

## Configuration

Layered TOML. System-wide at `/etc/ssh-notifier/config.toml`, per-user overrides at `~/.config/ssh-notifier/config.toml`. Per-user values merge on top per-key.

```toml
[detection]
backend = "auto"
ssh_port = 22
auth_timeout_seconds = 30

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

[[webhook.endpoints]]
url = "https://discord.com/api/webhooks/..."
timeout_seconds = 5
max_retries = 3
```

Template variables: `{event_type}`, `{username}`, `{source_ip}`, `{source_port}`, `{timestamp}`, `{session_id}`, `{pid}`.

Key behaviors:
- Per-user config wins over system config for that user's session.
- Merge is per-key for scalar and table values. Array values (like `[[webhook.endpoints]]`) are replaced entirely if present in user config, not appended.
- Invalid config fails fast at startup with error and line number.
- Live-reload via `inotify` file watch and `SIGHUP`.

## Systemd Integration & Privileges

Service file at `/etc/systemd/system/ssh-notifier.service`:

```ini
[Unit]
Description=SSH Connection Notifier
After=network.target sshd.service

[Service]
Type=notify
ExecStart=/usr/bin/ssh-notifier
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5

CapabilityBoundingSet=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH
AmbientCapabilities=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_ADMIN CAP_SETUID CAP_SETGID CAP_DAC_READ_SEARCH
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=/var/log/ssh-notifier.log
PrivateTmp=yes

[Install]
WantedBy=multi-user.target
```

Capabilities:
- `CAP_BPF` + `CAP_PERFMON` — load/attach BPF programs, read ring buffers
- `CAP_SYS_ADMIN` — BPF operations on older kernels
- `CAP_NET_ADMIN` — attach BPF to network tracepoints
- `CAP_SETUID` + `CAP_SETGID` — switch to target user for D-Bus/notify-send
- `CAP_DAC_READ_SEARCH` — read auth logs and user configs

Signal handling:
- `SIGHUP` — reload configuration
- `SIGTERM` / `SIGINT` — graceful shutdown (detach BPF, flush logs, drain notification queues)

## Build System & Project Structure

```
ssh-notifier/
├── build.zig                  # Compiles BPF C, embeds it, builds main binary
├── build.zig.zon              # Package manifest
├── src/
│   ├── main.zig               # Entry point, signal handling, sd_notify, startup
│   ├── config.zig             # TOML parser, layered merge, live-reload
│   ├── event.zig              # SSHEvent, session table, ring buffer
│   ├── detect/
│   │   ├── ebpf.zig           # libbpf CO-RE loader, ring buffer consumer
│   │   ├── journal.zig        # sd_journal subscription, pattern matching
│   │   ├── logfile.zig        # inotify log tailing, pattern matching
│   │   └── utmp.zig           # utmp polling
│   ├── notify/
│   │   ├── desktop.zig        # Session discovery, D-Bus, notify-send fallback
│   │   ├── logwriter.zig      # JSON-line log sink, SIGHUP rotation
│   │   └── webhook.zig        # HTTP POST, retry, payload templates
│   └── dbus.zig               # Minimal D-Bus wire protocol client
├── bpf/
│   ├── ssh_monitor.bpf.c      # BPF tracepoints source
│   └── ssh_monitor.h          # Shared event struct (BPF <-> userspace)
├── config/
│   ├── ssh-notifier.toml      # Example system config
│   └── ssh-notifier.service   # Systemd unit file
└── docs/
```

Build process:
1. `build.zig` invokes `zig cc` to compile `bpf/ssh_monitor.bpf.c` with `-target bpf` and CO-RE flags
2. BPF ELF object is `@embedFile`'d into the Zig binary
3. Main binary compiles as a static executable

Dependencies:
- libbpf — statically linked via Zig's C interop (`@cImport`)
- TOML parsing — use an existing Zig package (e.g. `zig-toml`) as a build dependency
- HTTP client — Zig's `std.http.Client`
- JSON serialization — Zig's `std.json`
- D-Bus wire protocol — minimal hand-rolled implementation (just `org.freedesktop.Notifications.Notify` method call)
- sd_notify — raw socket write to `$NOTIFY_SOCKET`, no libsystemd dependency

## Error Handling & Observability

### Startup sequence

1. Parse config (fail fast on invalid TOML)
2. Probe detection backends in priority order
3. Fall through to next backend if preferred one fails
4. Exit with clear error if no backend starts
5. Start sink threads
6. `sd_notify(READY=1)`
7. Begin event loop

### Runtime errors

- **BPF detach / kernel issue** — log error, fall back to journal/logfile. Exit if all backends fail (systemd restarts).
- **D-Bus connection lost** — retry with backoff, fall back to `notify-send` in the meantime.
- **Webhook unreachable** — exponential backoff (1s, 2s, 4s), max 3 retries, then drop event and log failure.
- **Log write failure** — log to stderr (journald), continue. Retry on next event.
- **Ring buffer full** — lagging sink skips to current write position, emits "dropped N events" warning.

### Self-monitoring

- Logs own health to stderr (journald): backend in use, sink status, event counts.
- `SIGUSR1` dumps status summary: uptime, backend, events processed, events dropped per sink, active sessions.

### Principle

The daemon prefers staying alive with reduced functionality over crashing. Only exits if no detection backend and no notification sink can operate.
