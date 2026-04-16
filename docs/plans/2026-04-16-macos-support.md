# macOS Support Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add macOS support with log stream, OpenBSM audit, and utmpx detection backends + osascript notifications, while keeping the Linux build working.

**Architecture:** Comptime platform conditionals (`builtin.os.tag`) gate platform-specific imports. Shared code (ring buffer, config, templates, patterns) stays platform-neutral. Platform backends live in `detect/linux/` and `detect/macos/` subdirectories.

**Tech Stack:** Zig 0.15.2, libbsm (macOS), osascript, launchd

**Spec:** `docs/specs/2026-04-16-macos-support.md`

---

## Phase 1: Platform Abstraction (Linux refactor, no macOS code)

These tasks restructure the codebase into platform directories while keeping Linux fully functional. No macOS code is written yet -- just preparing the foundation.

### Task 1: Extract `parseIPInto` to shared `ip.zig`

**Files:**
- Create: `src/detect/ip.zig`
- Modify: `src/detect/logfile.zig`
- Modify: `src/detect/journal.zig`
- Modify: `src/detect/utmp.zig`

- [ ] **Step 1: Create `src/detect/ip.zig`**

Copy `parseIPInto` and its test from `logfile.zig` into a new file:

```zig
// src/detect/ip.zig
const std = @import("std");

pub fn parseIPInto(ip_str: []const u8, out: *[16]u8) void {
    out.* = [_]u8{0} ** 16;
    out[10] = 0xff;
    out[11] = 0xff;
    var octets: [4]u8 = .{ 0, 0, 0, 0 };
    var idx: usize = 0;
    var cur: u16 = 0;
    for (ip_str) |ch| {
        if (ch == '.') {
            if (idx < 4) {
                octets[idx] = if (cur > 255) 255 else @intCast(cur);
                idx += 1;
                cur = 0;
            }
        } else if (ch >= '0' and ch <= '9') {
            cur = cur * 10 + (ch - '0');
        }
    }
    if (idx < 4) octets[idx] = if (cur > 255) 255 else @intCast(cur);
    out[12] = octets[0];
    out[13] = octets[1];
    out[14] = octets[2];
    out[15] = octets[3];
}

test "parseIPInto" {
    var ip: [16]u8 = undefined;
    parseIPInto("192.168.1.100", &ip);
    try std.testing.expectEqual(@as(u8, 192), ip[12]);
    try std.testing.expectEqual(@as(u8, 168), ip[13]);
    try std.testing.expectEqual(@as(u8, 1), ip[14]);
    try std.testing.expectEqual(@as(u8, 100), ip[15]);
}
```

- [ ] **Step 2: Update imports in `logfile.zig`, `journal.zig`, `utmp.zig`**

In `logfile.zig`: remove `parseIPInto` function and its test. Add `const ip = @import("ip.zig");`. Replace all calls from `parseIPInto(...)` to `ip.parseIPInto(...)`.

In `journal.zig` line 5: change `const logfile = @import("logfile.zig");` to `const ip = @import("ip.zig");`. Update line 72: `logfile.parseIPInto(...)` -> `ip.parseIPInto(...)`.

In `utmp.zig` line 4: change `const logfile = @import("logfile.zig");` to `const ip = @import("ip.zig");`. Update line 71: `logfile.parseIPInto(...)` -> `ip.parseIPInto(...)`.

- [ ] **Step 3: Run tests**

Run: `zig build test`
Expected: All tests pass (parseIPInto test now runs from ip.zig)

- [ ] **Step 4: Commit**

```bash
git add src/detect/ip.zig src/detect/logfile.zig src/detect/journal.zig src/detect/utmp.zig
git commit -m "refactor: extract parseIPInto to shared detect/ip.zig"
```

---

### Task 2: Move detection backends to `linux/` subdirectory

**Files:**
- Move: `src/detect/ebpf.zig` -> `src/detect/linux/ebpf.zig`
- Move: `src/detect/journal.zig` -> `src/detect/linux/journal.zig`
- Move: `src/detect/logfile.zig` -> `src/detect/linux/logfile.zig`
- Move: `src/detect/utmp.zig` -> `src/detect/linux/utmp.zig`

- [ ] **Step 1: Create directory and move files**

```bash
mkdir -p src/detect/linux
git mv src/detect/ebpf.zig src/detect/linux/
git mv src/detect/journal.zig src/detect/linux/
git mv src/detect/logfile.zig src/detect/linux/
git mv src/detect/utmp.zig src/detect/linux/
```

- [ ] **Step 2: Fix imports in all four files**

`src/detect/linux/ebpf.zig`:
- Line 2: `@import("../event.zig")` -> `@import("../../event.zig")`
- Line 3: `@import("../event.zig")` -> `@import("../../event.zig")`
- Line 4: `@import("backend.zig")` -> `@import("../backend.zig")`
- Line 62: `@embedFile("ssh_monitor.bpf.o")` -> `@embedFile("../ssh_monitor.bpf.o")`

`src/detect/linux/journal.zig`:
- Line 2: `@import("../event.zig")` -> `@import("../../event.zig")`
- Line 3: `@import("backend.zig")` -> `@import("../backend.zig")`
- Line 4: `@import("patterns.zig")` -> `@import("../patterns.zig")`
- Line 5: `@import("ip.zig")` -> `@import("../ip.zig")`

`src/detect/linux/logfile.zig`:
- Line 4: `@import("../event.zig")` -> `@import("../../event.zig")`
- Line 5: `@import("backend.zig")` -> `@import("../backend.zig")`
- Line 6: `@import("patterns.zig")` -> `@import("../patterns.zig")`
- `@import("ip.zig")` -> `@import("../ip.zig")` (Task 1 added this import)

`src/detect/linux/utmp.zig`:
- Line 2: `@import("../event.zig")` -> `@import("../../event.zig")`
- Line 3: `@import("backend.zig")` -> `@import("../backend.zig")`
- Line 4: `@import("ip.zig")` -> `@import("../ip.zig")` (Task 1 changed this from `logfile.zig` to `ip.zig`)

- [ ] **Step 3: Fix imports in `backend.zig`**

`src/detect/backend.zig` line 20: the `BackendType` enum stays as-is for now. But files that `backend.zig` references (if any) need updating. Currently `backend.zig` doesn't import any backend files -- it just defines the interface. No changes needed here yet.

- [ ] **Step 4: Fix imports in `main.zig`**

Lines 12-15:
```zig
const logfile = @import("detect/linux/logfile.zig");
const journal = @import("detect/linux/journal.zig");
const ebpf = @import("detect/linux/ebpf.zig");
const utmp_mod = @import("detect/linux/utmp.zig");
```

Line 269 (test block):
```zig
_ = @import("detect/linux/logfile.zig");
_ = @import("detect/linux/journal.zig");
_ = @import("detect/linux/ebpf.zig");
_ = @import("detect/linux/utmp.zig");
```

- [ ] **Step 5: Run tests and build**

Run: `zig build test && zig build`
Expected: All pass, binary works

- [ ] **Step 6: Commit**

```bash
git add src/detect/linux/ src/main.zig
git commit -m "refactor: move detection backends to detect/linux/"
```

---

### Task 3: Move notification desktop + dbus to `linux/` subdirectory

**Files:**
- Move: `src/notify/desktop.zig` -> `src/notify/linux/desktop.zig`
- Move: `src/dbus.zig` -> `src/notify/linux/dbus.zig`

- [ ] **Step 1: Create directory and move files**

```bash
mkdir -p src/notify/linux
git mv src/notify/desktop.zig src/notify/linux/
git mv src/dbus.zig src/notify/linux/
```

- [ ] **Step 2: Fix imports in `desktop.zig`**

`src/notify/linux/desktop.zig`:
- Line 2: `@import("../event.zig")` -> `@import("../../event.zig")`
- Line 3: `@import("../event.zig")` -> `@import("../../event.zig")`
- Line 4: `@import("../config.zig")` -> `@import("../../config.zig")`
- Line 5: `@import("../config.zig")` -> `@import("../../config.zig")`
- Line 6: `@import("../dbus.zig")` -> `@import("dbus.zig")` (same dir now)
- Line 7: `@import("../template.zig")` -> `@import("../../template.zig")`
- Line 8: `@import("sink.zig")` -> `@import("../sink.zig")`

- [ ] **Step 3: Fix imports in `main.zig`**

Line 17: `@import("notify/desktop.zig")` -> `@import("notify/linux/desktop.zig")`
Line 270 (test block): `@import("notify/desktop.zig")` -> `@import("notify/linux/desktop.zig")`
Line 269 (test block): `@import("dbus.zig")` -> `@import("notify/linux/dbus.zig")`

- [ ] **Step 4: Run tests and build**

Run: `zig build test && zig build`
Expected: All pass

- [ ] **Step 5: Commit**

```bash
git add src/notify/linux/ src/main.zig
git commit -m "refactor: move desktop notifications + dbus to notify/linux/"
```

---

### Task 4: Add comptime platform guards to `main.zig`

**Files:**
- Modify: `src/main.zig`

- [ ] **Step 1: Replace `std.os.linux` import with comptime conditional**

Line 3: replace `const linux = std.os.linux;` with:
```zig
const builtin = @import("builtin");
const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;
const linux = if (is_linux) std.os.linux else void;
```

- [ ] **Step 2: Guard backend imports with comptime**

Lines 12-15: replace the four direct imports with:
```zig
const logfile = if (is_linux) @import("detect/linux/logfile.zig") else void;
const journal = if (is_linux) @import("detect/linux/journal.zig") else void;
const ebpf = if (is_linux) @import("detect/linux/ebpf.zig") else void;
const utmp_mod = if (is_linux) @import("detect/linux/utmp.zig") else void;
const desktop = if (is_linux) @import("notify/linux/desktop.zig") else void;
```

Remove the old line 17 (`const desktop = @import("notify/desktop.zig");`). Note: macOS desktop import will be added in Phase 2.

- [ ] **Step 3: Fix signal setup**

Line 41: replace `linux.SA.RESTART` with a comptime expression:
```zig
.flags = if (is_linux) linux.SA.RESTART else 0,
```

Note: `posix.Sigaction.flags` type may differ. If Zig 0.15 provides `std.posix.SA.RESTART` on all targets, use that instead. Verify during build.

- [ ] **Step 4: Guard `sdNotify` function**

The function body references `linux.AF.UNIX`, `linux.SOCK.DGRAM`, `linux.sockaddr.un` etc. Since `linux` is `void` on macOS, these would fail even inside a runtime guard. Use a comptime-selected function instead:

Rename the existing `sdNotify` to `sdNotifyImpl`, then add:
```zig
const sdNotify = if (is_linux) sdNotifyImpl else struct {
    fn f(_: []const u8) void {}
}.f;
```

This completely eliminates the function body on macOS at compile time.

- [ ] **Step 5: Guard session timeout inference**

Line 148: change `if (backend_type != .ebpf)` to:
```zig
if (backend_type != .ebpf and backend_type != .audit_bsm) {
```

Both `ebpf` and `audit_bsm` produce auth events directly and don't need timeout inference. On Linux, `audit_bsm` is never selected so the extra check is harmless.

- [ ] **Step 6: Guard the test block**

Lines 255-272: wrap platform-specific imports in comptime:
```zig
test {
    _ = event;
    _ = @import("ring_buffer.zig");
    _ = @import("config.zig");
    _ = @import("template.zig");
    _ = @import("detect/patterns.zig");
    _ = @import("detect/backend.zig");
    _ = @import("detect/ip.zig");
    _ = @import("session.zig");
    _ = @import("notify/sink.zig");
    _ = @import("notify/logwriter.zig");
    _ = @import("notify/webhook.zig");
    if (is_linux) {
        _ = @import("detect/linux/logfile.zig");
        _ = @import("detect/linux/journal.zig");
        _ = @import("detect/linux/ebpf.zig");
        _ = @import("detect/linux/utmp.zig");
        _ = @import("notify/linux/dbus.zig");
        _ = @import("notify/linux/desktop.zig");
    }
}
```

- [ ] **Step 7: Run tests and build**

Run: `zig build test && zig build`
Expected: All pass on Linux

- [ ] **Step 8: Commit**

```bash
git add src/main.zig
git commit -m "refactor: add comptime platform guards to main.zig"
```

---

### Task 5: Make `backend.zig` platform-aware

**Files:**
- Modify: `src/detect/backend.zig`
- Modify: `src/event.zig`
- Modify: `src/config.zig`

- [ ] **Step 1: Expand `BackendType` enum in `backend.zig`**

Line 20: replace with:
```zig
pub const BackendType = enum {
    // Linux
    ebpf, journal, logfile, utmp,
    // macOS
    logstream, audit_bsm, utmpx_bsd,
};
```

- [ ] **Step 2: Make `probe()` platform-conditional**

Replace lines 22-38 with the platform-conditional probe from the spec:

```zig
const builtin = @import("builtin");
const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;

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

- [ ] **Step 3: Update test to be platform-aware**

Replace the probe test:
```zig
test "probe returns something on this system" {
    const config = Config{};
    if (is_linux or is_macos) {
        try std.testing.expect(probe(&config) != null);
    }
}
```

- [ ] **Step 4: Add macOS values to `event.zig` Backend enum**

In `src/event.zig`, add new values:
```zig
pub const Backend = enum(u8) {
    ebpf = 0, journal = 1, logfile = 2, utmp = 3,
    audit_bsm = 4, logstream = 5, utmpx_bsd = 6,

    pub fn toString(self: Backend) []const u8 {
        return switch (self) {
            .ebpf => "ebpf",
            .journal => "journal",
            .logfile => "logfile",
            .utmp => "utmp",
            .audit_bsm => "audit_bsm",
            .logstream => "logstream",
            .utmpx_bsd => "utmpx_bsd",
        };
    }
};
```

- [ ] **Step 5: Add macOS values to `config.zig` Backend enum**

In `src/config.zig`, add to the Backend enum and its `fromString`:
```zig
pub const Backend = enum {
    auto, ebpf, journal, logfile, utmp,
    audit_bsm, logstream, utmpx_bsd,

    pub fn fromString(s: []const u8) !Backend {
        if (std.mem.eql(u8, s, "auto")) return .auto;
        if (std.mem.eql(u8, s, "ebpf")) return .ebpf;
        if (std.mem.eql(u8, s, "journal")) return .journal;
        if (std.mem.eql(u8, s, "logfile")) return .logfile;
        if (std.mem.eql(u8, s, "utmp")) return .utmp;
        if (std.mem.eql(u8, s, "audit_bsm")) return .audit_bsm;
        if (std.mem.eql(u8, s, "logstream")) return .logstream;
        if (std.mem.eql(u8, s, "utmpx_bsd")) return .utmpx_bsd;
        return error.InvalidValue;
    }
};
```

- [ ] **Step 6: Update `runBackend` in `main.zig`**

Replace lines 181-188:
```zig
fn runBackend(backend_type: backend_mod.BackendType, ctx: *backend_mod.Context) void {
    switch (backend_type) {
        .logfile => if (is_linux) logfile.run(ctx),
        .journal => if (is_linux) journal.run(ctx),
        .ebpf => if (is_linux) ebpf.run(ctx),
        .utmp => if (is_linux) utmp_mod.run(ctx),
        .logstream => {}, // Phase 2
        .audit_bsm => {}, // Phase 2
        .utmpx_bsd => {}, // Phase 2
    }
}
```

- [ ] **Step 7: Run tests and build**

Run: `zig build test && zig build`
Expected: All pass on Linux. macOS backend stubs are no-ops.

- [ ] **Step 8: Commit**

```bash
git add src/detect/backend.zig src/event.zig src/config.zig src/main.zig
git commit -m "feat: expand Backend enums for macOS, platform-conditional probe()"
```

---

### Task 6: Update `build.zig` for platform-conditional linking

**Files:**
- Modify: `build.zig`

- [ ] **Step 1: Guard Linux library linking with OS check**

In `addExe()` function, wrap the Linux library links:
```zig
if (target.result.os.tag == .linux) {
    exe.root_module.linkSystemLibrary("libsystemd", .{});
    exe.root_module.linkSystemLibrary("bpf", .{});
}
if (target.result.os.tag == .macos) {
    exe.root_module.linkSystemLibrary("bsm", .{});
}
exe.root_module.link_libc = true;
```

- [ ] **Step 2: Guard BPF compilation step and make it optional**

The BPF compile step is Linux-only. Make it nullable so macOS targets can pass `null`:
```zig
const bpf_compile: ?*std.Build.Step = if (target.result.os.tag == .linux) blk: {
    const step = b.addSystemCommand(&.{ "sh", "-c", "test -f bpf/vmlinux.h && ..." });
    break :blk &step.step;
} else null;
```

- [ ] **Step 3: Change `addExe` to accept optional BPF step**

Change the `bpf_step` parameter from `*std.Build.Step` to `?*std.Build.Step`:
```zig
fn addExe(b: *std.Build, target: ..., bpf_step: ?*std.Build.Step) ... {
    // ... existing code ...
    // Line 106: change exe.step.dependOn(bpf_step) to:
    if (bpf_step) |step| exe.step.dependOn(step);
    return exe;
}
```

Existing call sites pass `&bpf_compile.step` which Zig coerces from `*Step` to `?*Step` automatically. After making `bpf_compile` nullable (Step 2), update the call sites to pass `bpf_compile` directly (it's already `?*Step`).

- [ ] **Step 4: Run build on Linux**

Run: `zig build test && zig build`
Expected: Linux build unchanged

- [ ] **Step 4: Commit**

```bash
git add build.zig
git commit -m "refactor: OS-conditional library linking in build.zig"
```

---

### Task 6b: Add `release-macos` build step and UPX conditional

**Files:**
- Modify: `build.zig`

Note: `addExe` already accepts `?*std.Build.Step` for bpf_step (changed in Task 6 Step 3).

- [ ] **Step 1: Guard UPX with Linux check in existing release steps**

In the `release` step block, wrap the UPX command:
```zig
if (resolved.result.os.tag == .linux) {
    const upx = b.addSystemCommand(&.{ "upx", "--best", "--lzma" });
    upx.addArg(b.getInstallPath(.{ .custom = "release" }, "ssh-watcher-x86_64-linux"));
    upx.step.dependOn(&install.step);
    release_step.dependOn(&upx.step);
} else {
    release_step.dependOn(&install.step);
}
```

Same pattern for `release-static`.

- [ ] **Step 2: Add `release-macos` build step**

Add after the `release-static` step:
```zig
// --- Release: macOS ---
// zig build release-macos
// Builds both x86_64 and aarch64 via cross-compilation. No UPX (breaks code signing).
const macos_step = b.step("release-macos", "Build macOS production binaries (ReleaseSmall, LTO, strip)");
inline for (.{
    .{ .arch = std.Target.Cpu.Arch.x86_64, .name = "x86_64-macos" },
    .{ .arch = std.Target.Cpu.Arch.aarch64, .name = "aarch64-macos" },
}) |rt| {
    const resolved = b.resolveTargetQuery(.{ .cpu_arch = rt.arch, .os_tag = .macos });
    const rel_exe = addExe(b, resolved, .ReleaseSmall, true, true, null);
    const install_artifact = b.addInstallArtifact(rel_exe, .{
        .dest_dir = .{ .override = .{ .custom = "release" } },
        .dest_sub_path = "ssh-watcher-" ++ rt.name,
    });
    macos_step.dependOn(&install_artifact.step);
}
```

- [ ] **Step 3: Build on Linux**

Run: `zig build test && zig build`
Expected: Linux build unchanged

- [ ] **Step 4: Commit**

```bash
git add build.zig
git commit -m "feat: add release-macos build target, guard UPX for Linux-only"
```

---

## Phase 2: macOS Backends

These tasks implement the three macOS detection backends. They can only be fully tested on macOS, but should compile on Linux as dead code (gated by comptime).

### Task 7: Create macOS log stream backend

**Files:**
- Create: `src/detect/macos/logstream.zig`
- Modify: `src/main.zig` (add import + runBackend case)

- [ ] **Step 1: Create directory**

```bash
mkdir -p src/detect/macos
```

- [ ] **Step 2: Create `src/detect/macos/logstream.zig`**

```zig
const std = @import("std");
const SSHEvent = @import("../../event.zig").SSHEvent;
const Context = @import("../backend.zig").Context;
const patterns = @import("../patterns.zig");
const ip = @import("../ip.zig");

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| {
        std.log.err("logstream backend: {}", .{err});
    };
}

fn runImpl(ctx: *Context) !void {
    var attempt: u8 = 0;
    while (attempt < 2 and !ctx.stopped()) : (attempt += 1) {
        if (attempt > 0) {
            std.log.warn("logstream: respawning log stream (attempt {d})", .{attempt + 1});
            std.Thread.sleep(5 * std.time.ns_per_s);
        }
        spawnAndRead(ctx) catch |err| {
            std.log.err("logstream: log stream exited: {}", .{err});
            continue;
        };
        return; // clean exit (ctx.stopped)
    }
    std.log.err("logstream: giving up after 2 attempts", .{});
}

fn spawnAndRead(ctx: *Context) !void {
    var child = std.process.Child.init(
        &.{ "log", "stream", "--process", "sshd", "--style", "compact", "--level", "info" },
        std.heap.page_allocator,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    defer {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    }

    const reader = child.stdout.?.reader();
    var line_buf: [4096]u8 = undefined;

    while (!ctx.stopped()) {
        const line = reader.readUntilDelimiter(&line_buf, '\n') catch |err| switch (err) {
            error.EndOfStream => return error.EndOfStream,
            else => continue,
        };
        processLine(ctx, line);
    }
}

fn processLine(ctx: *Context, line: []const u8) void {
    // Strip macOS log prefix: find "sshd[" and pass from there to patterns
    const marker = std.mem.indexOf(u8, line, "sshd[") orelse return;
    const sshd_line = line[marker..];

    const result = patterns.parseLine(sshd_line) orelse return;

    var ev = SSHEvent{ .backend = .logstream };
    ev.event_type = result.event_type;
    ev.setUsername(result.username);
    if (result.pid) |pid| {
        ev.pid = pid;
        ev.session_id = pid;
    }
    ip.parseIPInto(result.ip, &ev.source_ip);
    if (result.port) |port_str| {
        ev.source_port = std.fmt.parseInt(u16, port_str, 10) catch 0;
    }
    ev.timestamp = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
    ctx.emit(ev);
}
```

- [ ] **Step 3: Wire into `main.zig`**

Add comptime import (near line 15):
```zig
const logstream = if (is_macos) @import("detect/macos/logstream.zig") else void;
```

In `runBackend`, replace the `.logstream => {}` stub:
```zig
.logstream => if (is_macos) logstream.run(ctx),
```

Add to test block (inside a `if (is_macos)` guard):
```zig
if (is_macos) {
    _ = @import("detect/macos/logstream.zig");
}
```

- [ ] **Step 4: Build on Linux** (comptime dead code, should compile)

Run: `zig build test && zig build`
Expected: Pass (macOS code compiles away)

- [ ] **Step 5: Commit**

```bash
git add src/detect/macos/logstream.zig src/main.zig
git commit -m "feat: add macOS log stream detection backend"
```

---

### Task 8: Create macOS utmpx backend

**Files:**
- Create: `src/detect/macos/utmpx.zig`
- Modify: `src/main.zig`

- [ ] **Step 1: Create `src/detect/macos/utmpx.zig`**

```zig
const std = @import("std");
const SSHEvent = @import("../../event.zig").SSHEvent;
const Context = @import("../backend.zig").Context;

const c = @cImport({ @cInclude("utmpx.h"); });

const MAX_SESSIONS = 64;

pub fn run(ctx: *Context) void {
    var known: [MAX_SESSIONS]u32 = [_]u32{0} ** MAX_SESSIONS;
    var known_count: usize = 0;

    while (!ctx.stopped()) {
        var current: [MAX_SESSIONS]u32 = [_]u32{0} ** MAX_SESSIONS;
        var current_count: usize = 0;

        c.setutxent();
        while (c.getutxent()) |entry| {
            if (entry.*.ut_type != c.USER_PROCESS) continue;
            const host = std.mem.sliceTo(&entry.*.ut_host, 0);
            if (host.len == 0) continue; // local login, not SSH

            const pid: u32 = @intCast(entry.*.ut_pid);
            if (current_count < MAX_SESSIONS) {
                current[current_count] = pid;
                current_count += 1;
            }

            // Check if this is a new session
            var found = false;
            for (known[0..known_count]) |k| {
                if (k == pid) { found = true; break; }
            }
            if (!found) {
                var ev = SSHEvent{ .backend = .utmpx_bsd };
                ev.event_type = .auth_success;
                ev.pid = pid;
                ev.session_id = pid;
                ev.setUsername(std.mem.sliceTo(&entry.*.ut_user, 0));
                ev.timestamp = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
                // ut_host contains "hostname" or "IP" for SSH sessions
                // Not parsed as IP here -- would need ip.parseIPInto for dotted quad
                ctx.emit(ev);
            }
        }
        c.endutxent();

        // Detect disconnects: sessions in known but not in current
        for (known[0..known_count]) |k| {
            var still_here = false;
            for (current[0..current_count]) |cur| {
                if (cur == k) { still_here = true; break; }
            }
            if (!still_here) {
                var ev = SSHEvent{ .backend = .utmpx_bsd };
                ev.event_type = .disconnect;
                ev.pid = k;
                ev.session_id = k;
                ev.timestamp = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
                ctx.emit(ev);
            }
        }

        // Update known set
        known = current;
        known_count = current_count;

        std.Thread.sleep(2 * std.time.ns_per_s);
    }
}
```

- [ ] **Step 2: Wire into `main.zig`**

Add import:
```zig
const utmpx = if (is_macos) @import("detect/macos/utmpx.zig") else void;
```

In `runBackend`, replace stub:
```zig
.utmpx_bsd => if (is_macos) utmpx.run(ctx),
```

Add to macOS test block:
```zig
_ = @import("detect/macos/utmpx.zig");
```

- [ ] **Step 3: Build on Linux**

Run: `zig build test && zig build`
Expected: Pass

- [ ] **Step 4: Commit**

```bash
git add src/detect/macos/utmpx.zig src/main.zig
git commit -m "feat: add macOS utmpx detection backend"
```

---

### Task 9: Create macOS OpenBSM audit backend (stub)

**Files:**
- Create: `src/detect/macos/audit_bsm.zig`
- Modify: `src/main.zig`

Note: The OpenBSM API must be verified on an actual macOS machine before full implementation. This task creates a working stub that can be fleshed out once API signatures are confirmed.

- [ ] **Step 1: Create `src/detect/macos/audit_bsm.zig`**

```zig
const std = @import("std");
const SSHEvent = @import("../../event.zig").SSHEvent;
const Context = @import("../backend.zig").Context;

// TODO: Verify libbsm API on macOS 14+ before enabling.
// const c = @cImport({ @cInclude("bsm/libbsm.h"); });

pub fn run(ctx: *Context) void {
    std.log.err("audit_bsm: OpenBSM backend not yet implemented, use 'logstream' backend", .{});
    // Block until stopped so the daemon doesn't exit immediately
    while (!ctx.stopped()) {
        std.Thread.sleep(1 * std.time.ns_per_s);
    }
}
```

- [ ] **Step 2: Wire into `main.zig`**

Add import:
```zig
const audit_bsm = if (is_macos) @import("detect/macos/audit_bsm.zig") else void;
```

In `runBackend`, replace stub:
```zig
.audit_bsm => if (is_macos) audit_bsm.run(ctx),
```

- [ ] **Step 3: Build on Linux**

Run: `zig build test && zig build`
Expected: Pass

- [ ] **Step 4: Commit**

```bash
git add src/detect/macos/audit_bsm.zig src/main.zig
git commit -m "feat: add macOS OpenBSM audit backend (stub, needs API verification)"
```

---

## Phase 3: macOS Notifications

### Task 10: Create macOS osascript desktop notifications

**Files:**
- Create: `src/notify/macos/desktop.zig`
- Modify: `src/main.zig`

- [ ] **Step 1: Create directory**

```bash
mkdir -p src/notify/macos
```

- [ ] **Step 2: Create `src/notify/macos/desktop.zig`**

```zig
const std = @import("std");
const SSHEvent = @import("../../event.zig").SSHEvent;
const Config = @import("../../config.zig").Config;
const template = @import("../../template.zig");
const sink = @import("../sink.zig");

pub fn run(ctx: *sink.SinkContext) void {
    while (!ctx.stopped()) {
        if (ctx.consumer.pop()) |ev| {
            if (!sink.shouldNotify(ctx.config, ev.event_type)) continue;
            sendNotification(ctx.config, &ev);
        } else {
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }
    }
}

fn sendNotification(config: *const Config, ev: *const SSHEvent) void {
    var title_buf: [256]u8 = undefined;
    var body_buf: [512]u8 = undefined;
    const title = template.expand(config.title_template, ev, &title_buf) catch "SSH Event";
    const body = template.expand(config.body_template, ev, &body_buf) catch "unknown";

    // Escape title and body separately (each needs its own buffer)
    var esc_title_buf: [512]u8 = undefined;
    var esc_body_buf: [512]u8 = undefined;
    const esc_title = escapeAppleScript(title, &esc_title_buf);
    const esc_body = escapeAppleScript(body, &esc_body_buf);

    // Build osascript command: display notification "body" with title "title"
    var script_buf: [1536]u8 = undefined;
    const script = std.fmt.bufPrint(&script_buf, "display notification \"{s}\" with title \"{s}\"", .{
        esc_body, esc_title,
    }) catch return;

    var child = std.process.Child.init(
        &.{ "osascript", "-e", script },
        std.heap.page_allocator,
    );
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return;
    _ = child.wait() catch {};
}

/// Escape double quotes and backslashes for AppleScript string literals.
/// {username} comes from SSH auth data (attacker-controlled), so escaping is required.
fn escapeAppleScript(input: []const u8, buf: []u8) []const u8 {
    var i: usize = 0;
    for (input) |ch| {
        if (i + 2 > buf.len) break;
        if (ch == '"' or ch == '\\') {
            buf[i] = '\\';
            i += 1;
        }
        buf[i] = ch;
        i += 1;
    }
    return buf[0..i];
}
```

- [ ] **Step 3: Wire into `main.zig`**

Update the desktop import to be platform-conditional:
```zig
const desktop = if (is_linux) @import("notify/linux/desktop.zig")
    else if (is_macos) @import("notify/macos/desktop.zig")
    else void;
```

Add to macOS test block:
```zig
_ = @import("notify/macos/desktop.zig");
```

- [ ] **Step 4: Build on Linux**

Run: `zig build test && zig build`
Expected: Pass

- [ ] **Step 5: Commit**

```bash
git add src/notify/macos/desktop.zig src/main.zig
git commit -m "feat: add macOS osascript desktop notifications"
```

---

## Phase 4: Service, Packaging, CI

### Task 11: Create launchd plist and update install.sh

**Files:**
- Create: `config/com.moldabekov.ssh-watcher.plist`
- Modify: `install.sh`

- [ ] **Step 1: Create launchd plist**

Create `config/com.moldabekov.ssh-watcher.plist`:
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

- [ ] **Step 2: Update `install.sh` with platform detection**

Replace the install script with platform-aware version:
```sh
#!/bin/sh
set -e

PREFIX="${PREFIX:-/usr}"
SYSCONFDIR="${SYSCONFDIR:-/etc}"
OS="$(uname -s)"

# Find binary (release > dev build)
if [ -f "zig-out/release/ssh-watcher-x86_64-linux-static" ]; then
    BIN_SRC="zig-out/release/ssh-watcher-x86_64-linux-static"
elif [ -f "zig-out/release/ssh-watcher-x86_64-linux" ]; then
    BIN_SRC="zig-out/release/ssh-watcher-x86_64-linux"
elif [ -f "zig-out/release/ssh-watcher-x86_64-macos" ]; then
    BIN_SRC="zig-out/release/ssh-watcher-x86_64-macos"
elif [ -f "zig-out/release/ssh-watcher-aarch64-macos" ]; then
    BIN_SRC="zig-out/release/ssh-watcher-aarch64-macos"
elif [ -f "zig-out/bin/ssh-watcher" ]; then
    BIN_SRC="zig-out/bin/ssh-watcher"
else
    echo "Error: no binary found. Run 'zig build' first." >&2
    exit 1
fi

case "$OS" in
  Linux)
    BINDIR="$PREFIX/bin"
    SYSTEMDDIR="${SYSTEMDDIR:-/usr/lib/systemd/system}"
    install -Dm755 "$BIN_SRC" "$DESTDIR$BINDIR/ssh-watcher"
    install -Dm644 config/ssh-watcher.toml "$DESTDIR$SYSCONFDIR/ssh-watcher/config.toml"
    install -Dm644 config/ssh-watcher.service "$DESTDIR$SYSTEMDDIR/ssh-watcher.service"
    if [ -z "$DESTDIR" ] && command -v systemctl >/dev/null 2>&1; then
        systemctl daemon-reload
    fi
    echo "Start: sudo systemctl enable --now ssh-watcher"
    ;;
  Darwin)
    BINDIR="/usr/local/bin"
    PLISTDIR="/Library/LaunchDaemons"
    install -d "$DESTDIR$BINDIR"
    install -m 755 "$BIN_SRC" "$DESTDIR$BINDIR/ssh-watcher"
    install -d "$DESTDIR$SYSCONFDIR/ssh-watcher"
    install -m 644 config/ssh-watcher.toml "$DESTDIR$SYSCONFDIR/ssh-watcher/config.toml"
    install -d "$DESTDIR$PLISTDIR"
    install -m 644 config/com.moldabekov.ssh-watcher.plist "$DESTDIR$PLISTDIR/"
    # Ad-hoc codesign to avoid Gatekeeper quarantine
    codesign --sign - --force "$DESTDIR$BINDIR/ssh-watcher" 2>/dev/null || true
    echo "Start: sudo launchctl load /Library/LaunchDaemons/com.moldabekov.ssh-watcher.plist"
    ;;
  *)
    echo "Unsupported OS: $OS" >&2
    exit 1
    ;;
esac

echo "Installed ssh-watcher"
echo "  Binary: $DESTDIR$BINDIR/ssh-watcher"
echo "  Config: $DESTDIR$SYSCONFDIR/ssh-watcher/config.toml"
```

- [ ] **Step 3: Commit**

```bash
git add config/com.moldabekov.ssh-watcher.plist install.sh
git commit -m "feat: add launchd plist, platform-aware install.sh"
```

---

### Task 12: Add macOS CI job and update README

**Files:**
- Modify: `.github/workflows/release.yml`
- Modify: `README.md`

- [ ] **Step 1: Add macOS build job to CI**

Add after the `build-dynamic` job in `release.yml`:

The `release-macos` build step cross-compiles both x86_64 and aarch64 in one invocation, so only one CI job is needed. Use the runner's native Zig (aarch64 on `macos-latest`).

```yaml
  build-macos:
    name: macOS build (x86_64 + aarch64)
    runs-on: macos-latest
    steps:
      - uses: actions/checkout@v4

      - name: Cache Zig
        id: cache-zig-macos
        uses: actions/cache@v4
        with:
          path: zig-aarch64-macos-${{ env.ZIG_VERSION }}
          key: zig-macos-aarch64-${{ env.ZIG_VERSION }}
      - name: Install Zig
        if: steps.cache-zig-macos.outputs.cache-hit != 'true'
        run: curl -L "https://ziglang.org/download/$ZIG_VERSION/zig-aarch64-macos-$ZIG_VERSION.tar.xz" | tar xJ
      - name: Add Zig to PATH
        run: echo "$PWD/zig-aarch64-macos-$ZIG_VERSION" >> "$GITHUB_PATH"

      - name: Build both architectures
        run: zig build release-macos

      - name: Ad-hoc codesign
        run: |
          codesign --sign - --force zig-out/release/ssh-watcher-x86_64-macos
          codesign --sign - --force zig-out/release/ssh-watcher-aarch64-macos

      - name: Upload x86_64
        uses: actions/upload-artifact@v4
        with:
          name: ssh-watcher-x86_64-macos
          path: zig-out/release/ssh-watcher-x86_64-macos

      - name: Upload aarch64
        uses: actions/upload-artifact@v4
        with:
          name: ssh-watcher-aarch64-macos
          path: zig-out/release/ssh-watcher-aarch64-macos
```

Update the `release` job's `needs` to include `build-macos`, and add macOS artifacts to the release files.

- [ ] **Step 2: Update README**

Add macOS to the download table, building section, installation section, backend selection table, and project structure. Add macOS-specific notes about SIP, TCC, and Gatekeeper.

- [ ] **Step 3: Commit**

```bash
git add .github/workflows/release.yml README.md
git commit -m "feat: add macOS CI build, update README with macOS support"
```

---

## Verification Checklist (requires macOS machine)

These items cannot be verified on Linux and must be tested on macOS:

- [ ] `zig build` compiles on macOS
- [ ] `zig build test` passes on macOS
- [ ] `log stream --process sshd --style compact` produces expected output format
- [ ] `patterns.parseLine()` correctly parses macOS sshd log messages
- [ ] `log stream` stdout is line-buffered when piped (or events arrive within seconds)
- [ ] `osascript` notifications appear from a LaunchDaemon context
- [ ] `/dev/auditpipe` is accessible with root + SIP enabled (for audit_bsm backend)
- [ ] `getutxent()` returns SSH sessions on macOS 14+ (for utmpx backend)
- [ ] `std.posix.SA.RESTART` compiles on macOS target in Zig 0.15
- [ ] Ad-hoc codesigned binary runs without Gatekeeper warnings
