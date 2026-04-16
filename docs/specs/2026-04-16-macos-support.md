# macOS Support for ssh-watcher

## Overview

Add macOS support to ssh-watcher with three detection backends (log stream, OpenBSM audit, utmpx) and osascript notifications. The codebase uses Zig comptime conditionals to compile platform-appropriate code from a single source tree.

## Platform Abstraction

### Directory structure

Platform-specific code moves into `linux/` and `macos/` subdirectories. Shared utilities are extracted to the parent directory.

```
src/detect/
  backend.zig          # comptime platform switch + probe logic
  patterns.zig         # shared sshd log parser
  ip.zig               # shared parseIPInto (extracted from logfile.zig)
  linux/
    ebpf.zig
    journal.zig
    logfile.zig        # inotify-based, imports ../ip.zig
    utmp.zig           # imports ../ip.zig
  macos/
    audit_bsm.zig
    logstream.zig      # reuses ../patterns.zig
    utmpx.zig

src/notify/
  sink.zig             # shared
  logwriter.zig        # shared
  webhook.zig          # shared
  linux/
    desktop.zig        # D-Bus + fork+setuid
    dbus.zig           # moved from src/dbus.zig (Linux-only: uses linux.getuid)
  macos/
    desktop.zig        # osascript
```

### Comptime backend selection

`backend.zig` uses `@import("builtin").os.tag` to conditionally import backends:

```zig
const builtin = @import("builtin");
const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;

const ebpf = if (is_linux) @import("linux/ebpf.zig") else void;
const journal = if (is_linux) @import("linux/journal.zig") else void;
const logfile = if (is_linux) @import("linux/logfile.zig") else void;
const utmp = if (is_linux) @import("linux/utmp.zig") else void;

const logstream = if (is_macos) @import("macos/logstream.zig") else void;
const audit_bsm = if (is_macos) @import("macos/audit_bsm.zig") else void;
const utmpx = if (is_macos) @import("macos/utmpx.zig") else void;
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
| 1 | log stream | `log` CLI (always available, no SIP issues) |
| 2 | OpenBSM audit | /dev/auditpipe readable, root, SIP permitting |
| 3 | utmpx | Always available (deprecated since macOS 10.9, may produce no events on 13+) |

Note: log stream is priority 1 because it works on all macOS installations without SIP restrictions. OpenBSM audit may be blocked by SIP on default configurations (see Security Considerations below).

### Platform-neutral modules

These files require no platform-specific changes:

- `ring_buffer.zig`
- `template.zig`
- `session.zig`
- `notify/logwriter.zig`
- `notify/webhook.zig`
- `notify/sink.zig`
- `detect/patterns.zig`

### Modules requiring modification

These files are platform-neutral in concept but need specific changes:

- `event.zig` -- add three new Backend enum values
- `config.zig` -- add macOS backend values to Backend enum + `fromString()`, validate cross-platform (reject `backend = "ebpf"` on macOS, `backend = "audit_bsm"` on Linux)
- `main.zig` -- substantial rework: guard `std.os.linux` import, platform-conditional signal flags (`SA.RESTART`), comptime backend imports, platform-conditional sd_notify, guard test block
- `build.zig` -- OS-conditional library linking, BPF compilation guard, macOS release targets

### Files requiring move + modification

- `dbus.zig` -- move to `src/notify/linux/dbus.zig` (uses `linux.getuid()`, Linux-only)
- `src/detect/ebpf.zig` -- move to `src/detect/linux/ebpf.zig`, fix `@embedFile` path (currently `@embedFile("ssh_monitor.bpf.o")` resolves relative to file location; after move, must become `@embedFile("../../detect/ssh_monitor.bpf.o")` or move the `.bpf.o` file too)

### Shared utility extraction

`parseIPInto()` is currently in `logfile.zig` but used by `utmp.zig` and potentially by macOS backends. Extract to `src/detect/ip.zig` so both platform directories can import `../ip.zig`.

## macOS Detection Backends

### Log Stream (`macos/logstream.zig`) -- Priority 1

Parses sshd messages from macOS unified logging by spawning the `log` CLI.

**Approach:**
1. Spawn: `log stream --process sshd --style compact --level info`
2. Read stdout line by line
3. Strip the macOS log prefix to extract the sshd message
4. Pass to `patterns.parseLine()` (shared with Linux logfile backend)
5. Map ParseResult to SSHEvent and emit

**Log line format:** macOS `log stream --style compact` outputs lines like:
```
2024-01-15 10:30:45.123456-0700  localhost sshd[1234]: Accepted publickey for root from 192.168.1.1 port 54321 ssh2
```

**Prefix stripping:** Find `sshd[` or `sshd:` in the line, then extract everything from that point onward. This produces the same format that `patterns.parseLine()` expects (e.g., `sshd[1234]: Accepted publickey for root from ...`). The existing `extractPid()` in `patterns.zig` handles `sshd[PID]` (macOS uses `sshd`, not `sshd-session`).

**Events produced:** auth_success, auth_failure, disconnect (same patterns as Linux logfile/journal).

**Process management:** The `log stream` child process is spawned once at startup. If it exits unexpectedly, the backend attempts one respawn after a 5-second delay. If the second spawn also fails, the backend logs an error and exits (launchd KeepAlive handles daemon restart).

**Requirement:** sshd must be enabled on macOS (System Settings > General > Sharing > Remote Login).

### OpenBSM Audit (`macos/audit_bsm.zig`) -- Priority 2

macOS ships with BSM audit. The kernel writes audit records when sshd authenticates.

**Approach:**
1. Open `/dev/auditpipe` for real-time audit event streaming
2. Set preselection filter for login/auth events (classes `lo`, `aa`)
3. Read records with `au_read_rec()`, parse token stream with `au_fetch_tok()`
4. Extract: subject32/64 tokens (UID, PID), text tokens (username), addr tokens (IP), return tokens (success/failure)
5. Map to SSHEvent and emit

**C dependency:** `@cInclude("bsm/libbsm.h")` -- ships with Xcode Command Line Tools.

**API verification required:** The exact libbsm function signatures must be verified against the macOS 14+ SDK headers before implementation. Write a small C test program on an actual macOS machine that opens `/dev/auditpipe`, reads a record, and parses tokens to confirm the API surface.

**Events produced:** auth_success, auth_failure, disconnect (session close audit event).

**Limitation:** No raw TCP connection event (unlike eBPF's `inet_sock_set_state`). Connection events not available from this backend. SIP may block access to `/dev/auditpipe` (see Security Considerations).

### utmpx (`macos/utmpx.zig`) -- Priority 3

macOS has BSD utmpx via standard C API.

**Approach:**
1. Poll loop (same cadence as Linux utmp backend)
2. Call `setutxent()`, iterate with `getutxent()`, call `endutxent()`
3. Filter for `USER_PROCESS` type entries with `ut_host` set (SSH sessions)
4. Track seen sessions, emit auth_success for new entries
5. Emit disconnect when entries disappear

**C dependency:** `@cInclude("utmpx.h")` -- standard BSD header, ships with macOS.

**Events produced:** auth_success, disconnect (login/logout only, same limitation as Linux utmp).

**Deprecation warning:** Apple deprecated utmpx in macOS 10.9. As of macOS 13 (Ventura) and later, SSH sessions may not create utmpx entries depending on PAM configuration. This backend may produce zero events on modern macOS. It exists as a last-resort fallback only. The probe logic should log a warning if selected.

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

## Security Considerations (macOS-specific)

### SIP (System Integrity Protection)

SIP restricts access to `/dev/auditpipe` on default macOS installations. Even with root privileges, a process may be blocked from reading the audit pipe. This is why `log stream` is priority 1 -- it works without SIP modifications.

If the OpenBSM probe fails with a permission error, the backend should log a clear message: "OpenBSM audit requires SIP exception or `log stream` backend. Falling back."

### TCC (Transparency, Consent, and Control)

macOS TCC controls notification permissions. When `osascript` sends a notification from a LaunchDaemon running as root, macOS may:
- Show a system prompt asking for permission (may not be visible if no user is logged in)
- Silently suppress notifications from unsigned/unknown daemons

Mitigation: document in README that users may need to approve notifications in System Settings > Notifications after first run.

### Gatekeeper and Code Signing

Unsigned binaries downloaded from GitHub are quarantined by Gatekeeper. Users must run:
```bash
xattr -d com.apple.quarantine ssh-watcher
```

For a better experience, CI should apply ad-hoc code signing:
```bash
codesign --sign - --force ssh-watcher
```

This removes the quarantine issue without requiring an Apple Developer certificate. Document this in README.

## Event Type Mapping

The `Backend` enum in `event.zig` gains three new values:

```zig
pub const Backend = enum(u8) {
    ebpf = 0, journal = 1, logfile = 2, utmp = 3,
    audit_bsm = 4, logstream = 5, utmpx_bsd = 6,
};
```

These values appear in JSON log output and must remain stable for log consumers.

## main.zig Platform Rework

`main.zig` has five Linux-specific dependencies that need comptime guards:

1. **`const linux = std.os.linux`** -- guard with `if (is_linux)`
2. **Signal setup `linux.SA.RESTART`** -- use `std.posix.SA.RESTART` (portable) or comptime select
3. **Backend imports** -- all four backend imports are unconditional; must use comptime conditional imports matching `backend.zig`
4. **`sdNotify()` function** -- uses `linux.AF.UNIX`, `linux.SOCK.DGRAM`, `linux.SOCK.CLOEXEC`, `linux.sockaddr.un`, abstract socket `@` prefix. Entire function must be guarded with `if (is_linux)`
5. **`runBackend()` switch** -- only covers Linux backends; needs macOS branch
6. **Test block** (lines 255-272) -- unconditionally imports all Linux modules. Must be platform-guarded or split into platform-specific test files

## Build System

### build.zig changes

Detect target OS and link platform-appropriate libraries:

- **Linux:** `libsystemd`, `libbpf`, `libc` (unchanged)
- **macOS:** `libbsm`, `libc` (Xcode ships libbsm). No `-framework Foundation` needed for v1 (osascript is spawned, not linked).

BPF compilation step: guarded with `if (target.result.os.tag == .linux)`.

### Release targets

```
zig build release              # Linux x86_64 glibc (unchanged)
zig build release-static       # Linux x86_64 musl (unchanged)
zig build release-macos        # macOS x86_64 + aarch64
```

macOS release: ReleaseSmall + LTO + strip + ad-hoc codesign. No UPX (breaks macOS code signing).

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
    <key>UserName</key>
    <string>root</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>30</integer>
    <key>StandardOutPath</key>
    <string>/var/log/ssh-watcher.out</string>
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
  Linux)  install service to systemd, daemon-reload ;;
  Darwin) install plist to /Library/LaunchDaemons, codesign --sign - binary ;;
esac
```

### sd_notify

Guard with comptime: on macOS, the function becomes a no-op. launchd uses KeepAlive, no readiness protocol needed.

## Config paths

Same on both platforms:
- System: `/etc/ssh-watcher/config.toml`
- User: `~/.config/ssh-watcher/config.toml`
- Log: `/var/log/ssh-watcher.log`

## CI

### Cross-compilation limitation

macOS binaries cannot be cross-compiled from Linux CI runners. The `libbsm` dependency requires macOS system headers only available on macOS. A native macOS CI runner (`runs-on: macos-latest`) is required.

### Workflow addition

Add a macOS job to `.github/workflows/release.yml`:

```yaml
build-macos:
  name: macOS build
  runs-on: macos-latest
  strategy:
    matrix:
      arch: [x86_64, aarch64]
  steps:
    - uses: actions/checkout@v4
    - name: Install Zig
      # ... (same pattern as Linux)
    - name: Build
      run: zig build release-macos
    - name: Ad-hoc codesign
      run: codesign --sign - --force zig-out/release/ssh-watcher-*
    - name: Upload artifact
      uses: actions/upload-artifact@v4
```

No DEB/RPM for macOS. Release assets: raw binaries. Homebrew formula is future scope.

## Packaging (future scope)

- Homebrew formula (tap: `brew tap moldabekov/ssh-watcher`). No `depends_on` needed (static binary).
- `.pkg` installer with postinstall script.

Not in scope for v1.

## Files Changed Summary

| Action | Files |
|--------|-------|
| **New** | `src/detect/macos/audit_bsm.zig`, `src/detect/macos/logstream.zig`, `src/detect/macos/utmpx.zig`, `src/notify/macos/desktop.zig`, `src/detect/ip.zig`, `config/com.moldabekov.ssh-watcher.plist` |
| **Move** | `src/detect/{ebpf,journal,logfile,utmp}.zig` -> `src/detect/linux/`, `src/notify/desktop.zig` -> `src/notify/linux/desktop.zig`, `src/dbus.zig` -> `src/notify/linux/dbus.zig` |
| **Modify** | `src/detect/backend.zig`, `src/event.zig`, `src/config.zig`, `src/main.zig`, `build.zig`, `install.sh`, `.github/workflows/release.yml`, `README.md` |
| **Extract** | `parseIPInto()` from `logfile.zig` -> `src/detect/ip.zig` |
| **Unchanged** | `ring_buffer.zig`, `template.zig`, `session.zig`, `notify/logwriter.zig`, `notify/webhook.zig`, `notify/sink.zig`, `detect/patterns.zig` |

Note: `src/detect/linux/ebpf.zig` must update `@embedFile` path after move to account for new directory depth.
