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
    journal.zig        # imports ../ip.zig (currently uses logfile.parseIPInto)
    logfile.zig        # inotify-based, imports ../ip.zig
    utmp.zig           # imports ../ip.zig
  macos/
    audit_bsm.zig      # imports ../ip.zig
    logstream.zig      # reuses ../patterns.zig
    utmpx.zig

src/notify/
  sink.zig             # shared
  logwriter.zig        # shared
  webhook.zig          # shared
  linux/
    desktop.zig        # D-Bus + fork+setuid, imports dbus.zig
    dbus.zig           # moved from src/dbus.zig (Linux-only: uses linux.getuid)
  macos/
    desktop.zig        # osascript
```

### Import path changes for moved files

All moved files need relative import updates:

| File (new location) | Import change |
|---------------------|---------------|
| `detect/linux/ebpf.zig` | `@embedFile("ssh_monitor.bpf.o")` -> `@embedFile("../ssh_monitor.bpf.o")` |
| `detect/linux/ebpf.zig` | `@import("backend.zig")` -> `@import("../backend.zig")` |
| `detect/linux/ebpf.zig` | `@import("../event.zig")` -> `@import("../../event.zig")` |
| `detect/linux/journal.zig` | `@import("logfile.zig")` -> `@import("../ip.zig")` (use ip.parseIPInto) |
| `detect/linux/journal.zig` | `@import("backend.zig")` -> `@import("../backend.zig")` |
| `detect/linux/logfile.zig` | `@import("backend.zig")` -> `@import("../backend.zig")` |
| `detect/linux/utmp.zig` | `@import("logfile.zig")` -> `@import("../ip.zig")` |
| `detect/linux/utmp.zig` | `@import("backend.zig")` -> `@import("../backend.zig")` |
| `notify/linux/desktop.zig` | `@import("sink.zig")` -> `@import("../sink.zig")` |
| `notify/linux/desktop.zig` | `@import("../dbus.zig")` -> `@import("dbus.zig")` (same dir now) |
| `notify/linux/desktop.zig` | `@import("../template.zig")` -> `@import("../../template.zig")` |
| `notify/linux/desktop.zig` | `@import("../config.zig")` -> `@import("../../config.zig")` |
| `notify/linux/desktop.zig` | `@import("../event.zig")` -> `@import("../../event.zig")` |

All new macOS files follow the same depth pattern (e.g., `notify/macos/desktop.zig` imports `@import("../sink.zig")`).

### Comptime backend selection

`backend.zig` uses `@import("builtin").os.tag` to conditionally import backends:

```zig
const builtin = @import("builtin");
const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;

const ebpf = if (is_linux) @import("linux/ebpf.zig") else void;
const journal = if (is_linux) @import("linux/journal.zig") else void;
const logfile_mod = if (is_linux) @import("linux/logfile.zig") else void;
const utmp = if (is_linux) @import("linux/utmp.zig") else void;

const logstream = if (is_macos) @import("macos/logstream.zig") else void;
const audit_bsm = if (is_macos) @import("macos/audit_bsm.zig") else void;
const utmpx = if (is_macos) @import("macos/utmpx.zig") else void;
```

### Three Backend enums -- reconciliation

The codebase has three related enums that all need macOS values:

**1. `event.zig: Backend`** -- serialization enum, appears in JSON logs and wire format. Values must be stable.

```zig
pub const Backend = enum(u8) {
    ebpf = 0, journal = 1, logfile = 2, utmp = 3,
    audit_bsm = 4, logstream = 5, utmpx_bsd = 6,
};
```

**2. `config.zig: Backend`** -- user-configurable backend selection in TOML. Includes `auto`.

```zig
pub const Backend = enum {
    auto, ebpf, journal, logfile, utmp,
    audit_bsm, logstream, utmpx_bsd,
};
```

Cross-platform validation: at probe time (not parse time), if the user selects a backend that doesn't exist on the current platform, `probe()` returns null and the daemon exits with a clear error. This avoids comptime conditionals in the config parser. All values are accepted by `fromString()` on all platforms; the probe function handles platform rejection.

**3. `backend.zig: BackendType`** -- the probe return type and dispatch key used by `main.zig:runBackend()`. This is the operationally critical enum.

```zig
pub const BackendType = enum {
    // Linux
    ebpf, journal, logfile, utmp,
    // macOS
    logstream, audit_bsm, utmpx_bsd,
};
```

All three enums share tag names so `main.zig` can map between them (e.g., `BackendType.ebpf` matches `event.Backend.ebpf` by name).

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

### `backend.zig` probe() -- macOS logic

The current `probe()` function is entirely Linux-specific. It must become platform-conditional:

```zig
pub fn probe(config: *const Config) ?BackendType {
    const req = config.backend;
    if (is_linux) {
        if (req == .ebpf or req == .auto) {
            if (checkPath("/sys/kernel/btf/vmlinux")) return .ebpf;
            if (req == .ebpf) return null;
        }
        if (req == .journal or req == .auto) {
            if (checkPath("/run/systemd/system")) return .journal;
            if (req == .journal) return null;
        }
        if (req == .logfile or req == .auto) {
            if (checkPath("/var/log/auth.log") or checkPath("/var/log/secure")) return .logfile;
            if (req == .logfile) return null;
        }
        if (req == .utmp or req == .auto) return .utmp;
    }
    if (is_macos) {
        if (req == .logstream or req == .auto) {
            if (checkPath("/usr/bin/log")) return .logstream;
            if (req == .logstream) return null;
        }
        if (req == .audit_bsm or req == .auto) {
            if (checkPath("/dev/auditpipe")) return .audit_bsm;
            if (req == .audit_bsm) return null;
        }
        if (req == .utmpx_bsd or req == .auto) {
            std.log.warn("utmpx is deprecated on macOS 10.9+, may produce no events", .{});
            return .utmpx_bsd;
        }
    }
    return null;
}
```

The test block at the end of `backend.zig` must also be guarded or made platform-aware.

### Platform-neutral modules

These files require no platform-specific changes:

- `ring_buffer.zig`
- `template.zig`
- `session.zig`
- `notify/logwriter.zig`
- `notify/webhook.zig`
- `notify/sink.zig`

### Modules requiring modification

- `event.zig` -- add three new Backend enum values + `toString()` cases
- `config.zig` -- add macOS backend values to `Backend.fromString()`
- `main.zig` -- substantial rework (see dedicated section below)
- `build.zig` -- OS-conditional library linking, BPF compilation guard, macOS release targets, UPX conditional (Linux only)
- `detect/backend.zig` -- comptime imports, platform-conditional `probe()`, expanded `BackendType` enum
- `detect/patterns.zig` -- no code changes, but verify macOS sshd uses same log message patterns (see Verification Items)

### Files requiring move + modification

- `dbus.zig` -> `src/notify/linux/dbus.zig` (uses `linux.getuid()`, Linux-only)
- `detect/ebpf.zig` -> `detect/linux/ebpf.zig` (fix `@embedFile` to `../ssh_monitor.bpf.o`)
- `detect/journal.zig` -> `detect/linux/journal.zig` (change `logfile.parseIPInto` to `ip.parseIPInto`)
- `detect/logfile.zig` -> `detect/linux/logfile.zig` (extract `parseIPInto` to `ip.zig`)
- `detect/utmp.zig` -> `detect/linux/utmp.zig` (change `logfile.parseIPInto` to `ip.parseIPInto`)
- `notify/desktop.zig` -> `notify/linux/desktop.zig` (all import paths change)

### Shared utility extraction

`parseIPInto()` is currently in `logfile.zig` but used by three files:
- `utmp.zig` (line 71)
- `journal.zig` (line 72)
- potentially `macos/audit_bsm.zig`

Extract to `src/detect/ip.zig`. The function only handles IPv4 dotted-quad format. macOS sshd may log IPv6 addresses (e.g., `::1` for localhost). Document IPv6 as a known limitation for v1; the function clamps to `0.0.0.0` for non-IPv4 input.

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

**Prefix stripping:** Find `sshd[` in the line, then extract everything from that point onward. This produces the same format that `patterns.parseLine()` expects (e.g., `sshd[1234]: Accepted publickey for root from ...`). The existing `extractPid()` in `patterns.zig` handles `sshd[PID]` (macOS uses `sshd`, not `sshd-session`).

**Stdout buffering caveat:** When a child process writes to a pipe (not a terminal), libc typically switches to full buffering (4-8KB blocks). The macOS `log stream` command may or may not flush after each line when piped. If it uses full buffering, events arrive in delayed bursts instead of real-time. Mitigation options:
- Use `script -q /dev/null log stream ...` to force a pseudo-terminal (line-buffered)
- Accept the latency (events within seconds, not sub-second)
- Test on actual macOS to determine `log stream` behavior when piped

**Events produced:** auth_success, auth_failure, disconnect (same patterns as Linux logfile/journal).

**Process management:** The `log stream` child process is spawned once at startup. If it exits unexpectedly, the backend attempts one respawn after a 5-second delay. If the second spawn also fails, the backend logs an error and exits (launchd KeepAlive handles daemon restart).

**Requirement:** sshd must be enabled on macOS (System Settings > General > Sharing > Remote Login).

### OpenBSM Audit (`macos/audit_bsm.zig`) -- Priority 2

macOS ships with BSM audit. The kernel writes audit records when sshd authenticates.

**Approach:**
1. Open `/dev/auditpipe` for real-time audit event streaming
2. Set preselection filter for login/auth events (classes `lo`, `aa`)
3. Read raw audit records, parse BSM token stream
4. Extract: subject32/64 tokens (UID, PID), text tokens (username), addr tokens (IP), return tokens (success/failure)
5. Map to SSHEvent and emit

**C dependency:** `@cInclude("bsm/libbsm.h")` -- ships with Xcode Command Line Tools.

**API verification required:** The exact libbsm function signatures and token parsing approach must be verified against the macOS 14+ SDK headers before implementation. Write a small C test program on an actual macOS machine that:
1. Opens `/dev/auditpipe`
2. Reads at least one audit record
3. Parses tokens from it
4. Confirms which functions and structs are available

Do this before writing any Zig code for this backend.

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
- `desktop.zig` on Linux has 6+ direct `std.os.linux.*` syscalls (getuid, setuid, setgid, setgroups, syscall2) -- the macOS version shares nothing except the interface.

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

For a better experience, CI applies ad-hoc code signing:
```bash
codesign --sign - --force ssh-watcher-aarch64-macos
codesign --sign - --force ssh-watcher-x86_64-macos
```

This removes the quarantine issue without requiring an Apple Developer certificate. Document both options in README.

## main.zig Platform Rework

`main.zig` has six Linux-specific dependencies that need comptime guards:

1. **`const linux = std.os.linux`** -- guard with `if (is_linux)`. Use: `const linux = if (is_linux) std.os.linux else void;`
2. **Signal setup `linux.SA.RESTART`** -- verify `std.posix.SA.RESTART` exists on macOS target in Zig 0.15. If not, use comptime select. Flag as verification item.
3. **Backend imports** (lines 12-18) -- all four backend imports are unconditional and reference Linux-only files. Must use comptime conditional imports matching `backend.zig`. On macOS, import macOS backends instead.
4. **`sdNotify()` function** -- uses `linux.AF.UNIX`, `linux.SOCK.DGRAM`, `linux.SOCK.CLOEXEC`, `linux.sockaddr.un`, abstract socket `@` prefix. Entire function must be wrapped: `const sdNotify = if (is_linux) sdNotifyImpl else struct { fn f() void {} }.f;`
5. **`runBackend()` switch** -- only covers Linux backends. Add macOS branch with `logstream.run`, `audit_bsm.run`, `utmpx.run`.
6. **Test block** (lines 255-272) -- unconditionally imports all Linux modules (`dbus`, `logfile`, `journal`, `ebpf`, `utmp`). On macOS, `zig build test` would fail. Must be platform-guarded: `test { if (is_linux) { ... } }`

## Build System

### build.zig changes

Detect target OS and link platform-appropriate libraries:

- **Linux:** `libsystemd`, `libbpf`, `libc` (unchanged)
- **macOS:** `libbsm`, `libc` (Xcode ships libbsm). No `-framework Foundation` needed for v1.

BPF compilation step: guarded with `if (target.result.os.tag == .linux)`.
UPX compression step: guarded with `if (target.result.os.tag == .linux)` -- UPX breaks macOS code signing.

### Release targets

```
zig build release              # Linux x86_64 glibc (unchanged)
zig build release-static       # Linux x86_64 musl (unchanged)
zig build release-macos        # macOS, needs -Dtarget= for arch selection
```

The `release-macos` step in build.zig must accept a target architecture parameter. CI matrix runs it twice (x86_64, aarch64) to produce both binaries.

macOS release: ReleaseSmall + LTO + strip + ad-hoc codesign. No UPX.

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

Note: macOS will have three log files (`ssh-watcher.log` from the app, plus `.out`/`.err` from launchd). On Linux, journald captures stdout/stderr. Document this difference in README.

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

macOS binaries cannot be cross-compiled from Linux CI runners. The `libbsm` dependency requires macOS system headers only available on macOS. A native macOS CI runner (`runs-on: macos-latest`) is required. Note: macOS runners cost more on GitHub Actions.

### Workflow addition

Add a macOS job to `.github/workflows/release.yml`:

```yaml
build-macos:
  name: macOS build (${{ matrix.arch }})
  runs-on: macos-latest
  strategy:
    matrix:
      arch: [x86_64, aarch64]
  steps:
    - uses: actions/checkout@v4
    - name: Install Zig
      # ... (same pattern as Linux)
    - name: Build
      run: zig build release-macos -Dtarget=${{ matrix.arch }}-macos
    - name: Ad-hoc codesign
      run: codesign --sign - --force zig-out/release/ssh-watcher-${{ matrix.arch }}-macos
    - name: Upload artifact
      uses: actions/upload-artifact@v4
      with:
        name: ssh-watcher-${{ matrix.arch }}-macos
        path: zig-out/release/ssh-watcher-${{ matrix.arch }}-macos
```

No DEB/RPM for macOS. Release assets: raw binaries. Homebrew formula is future scope.

## Packaging (future scope)

- Homebrew formula (tap: `brew tap moldabekov/ssh-watcher`). No `depends_on` needed (compiled binary).
- `.pkg` installer with postinstall script.

Not in scope for v1.

## Verification Items

These must be confirmed on an actual macOS machine before or during implementation:

1. **OpenBSM API surface** -- write a C test program to confirm libbsm function signatures against macOS 14+ SDK
2. **`std.posix.SA.RESTART`** -- confirm this exists in Zig 0.15 when targeting macOS
3. **`log stream` buffering** -- test whether `log stream --process sshd` line-buffers when piped to a non-terminal
4. **`patterns.parseLine()` compatibility** -- confirm macOS sshd uses the same log message patterns ("Accepted password/publickey for", "Failed password for", "Disconnected from user", "Connection closed by")
5. **utmpx population** -- confirm whether macOS 14+ creates utmpx entries for SSH sessions
6. **SIP and `/dev/auditpipe`** -- confirm whether root can open `/dev/auditpipe` on a default macOS install with SIP enabled
7. **TCC and osascript** -- confirm whether a LaunchDaemon can send notifications via osascript without prior TCC approval

## Files Changed Summary

| Action | Files |
|--------|-------|
| **New** | `src/detect/macos/audit_bsm.zig`, `src/detect/macos/logstream.zig`, `src/detect/macos/utmpx.zig`, `src/notify/macos/desktop.zig`, `src/detect/ip.zig`, `config/com.moldabekov.ssh-watcher.plist` |
| **Move + modify** | `src/detect/{ebpf,journal,logfile,utmp}.zig` -> `src/detect/linux/` (fix all import paths), `src/notify/desktop.zig` -> `src/notify/linux/desktop.zig` (fix import paths), `src/dbus.zig` -> `src/notify/linux/dbus.zig` |
| **Modify** | `src/detect/backend.zig` (3-enum expansion, platform probe), `src/event.zig` (new Backend values), `src/config.zig` (new Backend.fromString values), `src/main.zig` (6 Linux deps to guard), `build.zig` (OS-conditional linking, UPX guard, macOS targets), `install.sh` (platform detection), `.github/workflows/release.yml` (macOS CI job), `README.md` |
| **Extract** | `parseIPInto()` from `logfile.zig` -> `src/detect/ip.zig` (used by journal, utmp, logfile, audit_bsm) |
| **Unchanged** | `ring_buffer.zig`, `template.zig`, `session.zig`, `notify/logwriter.zig`, `notify/webhook.zig`, `notify/sink.zig`, `detect/patterns.zig` |
