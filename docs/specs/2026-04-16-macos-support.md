# macOS Support for ssh-watcher

## Overview

Add macOS support to ssh-watcher with three detection backends (OpenBSM audit, log stream, utmpx) and osascript notifications. The codebase uses Zig comptime conditionals to compile platform-appropriate code from a single source tree.

## Platform Abstraction

### Directory structure

Platform-specific code moves into `linux/` and `macos/` subdirectories:

```
src/detect/
  backend.zig          # comptime platform switch + probe logic
  patterns.zig         # shared sshd log parser
  linux/
    ebpf.zig
    journal.zig
    logfile.zig        # inotify-based
    utmp.zig
  macos/
    audit_bsm.zig
    logstream.zig      # reuses patterns.zig
    utmpx.zig

src/notify/
  sink.zig             # shared
  logwriter.zig        # shared
  webhook.zig          # shared
  linux/
    desktop.zig        # D-Bus + fork+setuid
  macos/
    desktop.zig        # osascript
```

### Comptime backend selection

`backend.zig` uses `@import("builtin").os.tag` to conditionally import backends:

```zig
const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;

const ebpf = if (is_linux) @import("linux/ebpf.zig") else void;
const audit_bsm = if (is_macos) @import("macos/audit_bsm.zig") else void;
```

### Backend priority

Linux (unchanged):

| Priority | Backend | Requirements |
|----------|---------|-------------|
| 1 | eBPF | Kernel 5.8+, BTF, CAP_BPF |
| 2 | journal | systemd |
| 3 | logfile | /var/log/secure or /var/log/auth.log |
| 4 | utmp | Always available |

macOS:

| Priority | Backend | Requirements |
|----------|---------|-------------|
| 1 | OpenBSM audit | /dev/auditpipe readable, root |
| 2 | log stream | `log` CLI (always available) |
| 3 | utmpx | Always available |

### Unchanged modules

These files are platform-neutral and require no changes:

- `event.zig` (add new Backend enum values)
- `ring_buffer.zig`
- `config.zig`
- `template.zig`
- `session.zig`
- `notify/logwriter.zig`
- `notify/webhook.zig`
- `notify/sink.zig`
- `detect/patterns.zig`

## macOS Detection Backends

### OpenBSM Audit (`macos/audit_bsm.zig`)

macOS ships with BSM audit. The kernel writes audit records when sshd authenticates.

**Approach:**
1. Open `/dev/auditpipe` for real-time audit event streaming
2. Set preselection filter for login/auth events (classes `lo`, `aa`, `au`)
3. Parse BSM token stream: subject32/64 tokens (UID, PID), text tokens (username), addr tokens (IP), return tokens (success/failure)
4. Map to SSHEvent and emit

**C dependency:** `@cInclude("bsm/libbsm.h")` -- ships with Xcode Command Line Tools. Functions: `au_read_rec()`, `au_fetch_tok()`.

**Events produced:** auth_success, auth_failure, disconnect (session close audit event).

**Limitation:** No raw TCP connection event (unlike eBPF's `inet_sock_set_state`). Connection events not available from this backend.

### Log Stream (`macos/logstream.zig`)

Parses sshd messages from macOS unified logging by spawning the `log` CLI.

**Approach:**
1. Spawn: `log stream --process sshd --style compact --level info`
2. Read stdout line by line
3. Extract the sshd message portion from each line
4. Pass to `patterns.parseLine()` (shared with Linux logfile backend)
5. Map ParseResult to SSHEvent and emit

**Events produced:** auth_success, auth_failure, disconnect (same patterns as Linux logfile/journal).

**Process management:** The `log stream` child process is spawned once at startup. If it exits, the backend logs an error. The daemon's restart logic (systemd/launchd) handles recovery.

**Requirement:** sshd must be enabled on macOS (`System Preferences > Sharing > Remote Login`).

### utmpx (`macos/utmpx.zig`)

macOS has BSD utmpx via standard C API.

**Approach:**
1. Poll loop (same cadence as Linux utmp backend)
2. Call `setutxent()`, iterate with `getutxent()`, call `endutxent()`
3. Filter for `USER_PROCESS` type entries with `ut_host` set (SSH sessions)
4. Track seen sessions, emit auth_success for new entries
5. Emit disconnect when entries disappear

**C dependency:** `@cInclude("utmpx.h")` -- standard BSD header, ships with macOS.

**Events produced:** auth_success, disconnect (login/logout only, same limitation as Linux utmp).

## macOS Notifications (`macos/desktop.zig`)

Desktop notifications via `osascript`:

```
osascript -e 'display notification "body" with title "title"'
```

**Key differences from Linux:**
- No UID iteration -- macOS is single-active-user. Notify the console user.
- No fork+setuid -- osascript runs in the console user's context.
- No D-Bus -- `dbus.zig` is not compiled on macOS.

**Urgency mapping:** macOS `display notification` has no urgency levels. All urgencies produce the same notification. Critical urgency could optionally use `display alert` instead (modal dialog), but for v1 all use `display notification`.

## Event Type Mapping

The `Backend` enum in `event.zig` gains three new values:

```zig
pub const Backend = enum(u8) {
    ebpf = 0, journal = 1, logfile = 2, utmp = 3,
    audit_bsm = 4, logstream = 5, utmpx_bsd = 6,
};
```

## Build System

### build.zig changes

Detect target OS and link platform-appropriate libraries:

- **Linux:** `libsystemd`, `libbpf`, `libc` (unchanged)
- **macOS:** `libbsm`, `libc` (Xcode ships libbsm)

BPF compilation step: guarded with `if (target.os.tag == .linux)`.

### Release targets

Add macOS targets:

```
zig build release              # Linux x86_64 glibc (unchanged)
zig build release-static       # Linux x86_64 musl (unchanged)
zig build release-macos        # macOS x86_64 + aarch64
```

macOS release: ReleaseSmall + LTO + strip. No UPX (breaks macOS code signing).

## Service Management

### launchd plist

New file: `config/com.moldabekov.ssh-watcher.plist`

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>com.moldabekov.ssh-watcher</string>
    <key>ProgramArguments</key>
    <array><string>/usr/local/bin/ssh-watcher</string></array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardErrorPath</key>
    <string>/var/log/ssh-watcher.err</string>
</dict>
</plist>
```

Install to `/Library/LaunchDaemons/` (runs as root).

### install.sh changes

Platform detection:

```sh
case "$(uname -s)" in
  Linux)  install service to systemd ;;
  Darwin) install plist to /Library/LaunchDaemons ;;
esac
```

### sd_notify

`main.zig` already calls `sd_notify`. Guard with comptime: on macOS, skip the call (launchd uses KeepAlive, no readiness protocol needed).

## Config paths

Same on both platforms:
- System: `/etc/ssh-watcher/config.toml`
- User: `~/.config/ssh-watcher/config.toml`
- Log: `/var/log/ssh-watcher.log`

## CI

Add a macOS job to `.github/workflows/release.yml`:

```yaml
build-macos:
  name: macOS build (universal)
  runs-on: macos-latest
  steps:
    - checkout
    - zig build release-macos
    - upload artifacts: ssh-watcher-x86_64-macos, ssh-watcher-aarch64-macos
```

No DEB/RPM for macOS. Release assets: raw binaries (or future Homebrew formula).

## Packaging

macOS packages for future consideration:
- Homebrew formula (tap or core)
- `.pkg` installer

Not in scope for v1. Raw binary + `install.sh` is sufficient.

## Files Changed Summary

| Action | Files |
|--------|-------|
| **New** | `src/detect/macos/audit_bsm.zig`, `src/detect/macos/logstream.zig`, `src/detect/macos/utmpx.zig`, `src/notify/macos/desktop.zig`, `config/com.moldabekov.ssh-watcher.plist` |
| **Move** | `src/detect/{ebpf,journal,logfile,utmp}.zig` → `src/detect/linux/`, `src/notify/desktop.zig` → `src/notify/linux/desktop.zig` |
| **Modify** | `src/detect/backend.zig`, `src/event.zig`, `src/main.zig`, `build.zig`, `install.sh`, `.github/workflows/release.yml`, `README.md` |
| **Unchanged** | `ring_buffer.zig`, `config.zig`, `template.zig`, `session.zig`, `patterns.zig`, `logwriter.zig`, `webhook.zig`, `sink.zig`, `dbus.zig` |
