# SSH Notifier Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a Zig daemon that monitors SSH connections via pluggable detection backends (eBPF, journal, logfile, utmp) and dispatches notifications through desktop notifications, log files, and webhooks.

**Architecture:** Single-binary monolith. One detection thread writes SSHEvent structs into a broadcast ring buffer. Each notification sink runs in its own thread, consuming events independently. Config is layered TOML (system + per-user). Runs as a systemd service with capabilities for eBPF and user session access.

**Tech Stack:** Zig 0.15.2, libbpf 1.6.0 (C interop), BPF CO-RE, D-Bus wire protocol, inotify, `std.http.Client`

---

## Prerequisites

- Zig 0.15.2 at `/opt/zig/zig`
- libbpf-devel 1.6.0 (`/usr/include/bpf/`)
- bpftool 7.6.0 (`/usr/sbin/bpftool`)
- BTF available at `/sys/kernel/btf/vmlinux`
- AlmaLinux 10.1, kernel 6.12

Generate vmlinux.h (needed for BPF CO-RE in Task 11):

```bash
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

## File Structure

```
ssh-notifier/
├── build.zig                     # Build script: compiles BPF, links libbpf, builds binary
├── build.zig.zon                 # Package manifest
├── src/
│   ├── main.zig                  # Entry point, startup, signal handling, main loop
│   ├── event.zig                 # SSHEvent, EventType, serialization helpers
│   ├── ring_buffer.zig           # BroadcastBuffer(T) - single-producer multi-consumer
│   ├── config.zig                # Config struct, TOML parser, layered merge
│   ├── template.zig              # Template variable expansion for notifications
│   ├── session.zig               # Session correlation table (LRU, timeout-based eviction)
│   ├── detect/
│   │   ├── backend.zig           # Backend interface (tagged union)
│   │   ├── ebpf.zig              # libbpf CO-RE loader, BPF ring buffer consumer
│   │   ├── journal.zig           # sd_journal subscription, log parsing
│   │   ├── logfile.zig           # inotify-based log tailing, log parsing
│   │   ├── utmp.zig              # utmp polling
│   │   └── patterns.zig          # sshd log line pattern matching (shared)
│   ├── notify/
│   │   ├── sink.zig              # Sink interface (tagged union)
│   │   ├── desktop.zig           # Session discovery, D-Bus + notify-send fallback
│   │   ├── logwriter.zig         # JSON-line log output
│   │   └── webhook.zig           # HTTP POST, retry, payload templates
│   └── dbus.zig                  # Minimal D-Bus wire protocol client
├── bpf/
│   ├── ssh_monitor.bpf.c         # BPF tracepoints (inet_csk_accept, sched_process_exec/exit)
│   ├── ssh_monitor.h             # Shared event struct (BPF <-> userspace)
│   └── vmlinux.h                 # Generated from BTF (not committed)
├── config/
│   ├── ssh-notifier.toml         # Example system config
│   └── ssh-notifier.service      # Systemd unit file
└── .gitignore
```

---

## Task 1: Project Scaffold & Event Model

**Files:**
- Create: `build.zig`
- Create: `build.zig.zon`
- Create: `src/main.zig`
- Create: `src/event.zig`
- Create: `.gitignore`

- [ ] **Step 1: Create build files and .gitignore**

`.gitignore`:
```
zig-out/
zig-cache/
.zig-cache/
bpf/vmlinux.h
bpf/*.bpf.o
```

`build.zig.zon`:
```zig
.{
    .name = .{ .override = "ssh-notifier" },
    .version = "0.1.0",
    .fingerprint = .auto,
    .paths = .{
        "build.zig",
        "build.zig.zon",
        "src",
    },
}
```

`build.zig`:
```zig
const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "ssh-notifier",
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }
    const run_step = b.step("run", "Run ssh-notifier");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const run_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_tests.step);
}
```

- [ ] **Step 2: Write event model with tests**

`src/event.zig`:
```zig
const std = @import("std");

pub const EventType = enum(u8) {
    connection = 0,
    auth_success = 1,
    auth_failure = 2,
    disconnect = 3,

    pub fn toString(self: EventType) []const u8 {
        return switch (self) {
            .connection => "connection",
            .auth_success => "auth_success",
            .auth_failure => "auth_failure",
            .disconnect => "disconnect",
        };
    }
};

pub const SSHEvent = struct {
    timestamp: u64 = 0,
    event_type: EventType = .connection,
    source_ip: [16]u8 = [_]u8{0} ** 16,
    source_port: u16 = 0,
    username: [64]u8 = [_]u8{0} ** 64,
    pid: u32 = 0,
    session_id: u64 = 0,

    pub fn setIPv4(self: *SSHEvent, a: u8, b: u8, c_byte: u8, d: u8) void {
        self.source_ip = [_]u8{0} ** 16;
        self.source_ip[10] = 0xff;
        self.source_ip[11] = 0xff;
        self.source_ip[12] = a;
        self.source_ip[13] = b;
        self.source_ip[14] = c_byte;
        self.source_ip[15] = d;
    }

    pub fn ipv4Slice(self: *const SSHEvent) [4]u8 {
        return .{ self.source_ip[12], self.source_ip[13], self.source_ip[14], self.source_ip[15] };
    }

    pub fn formatIP(self: *const SSHEvent, buf: []u8) ![]const u8 {
        const ip = self.ipv4Slice();
        return std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{ ip[0], ip[1], ip[2], ip[3] });
    }

    pub fn setUsername(self: *SSHEvent, name: []const u8) void {
        self.username = [_]u8{0} ** 64;
        const len = @min(name.len, 63);
        @memcpy(self.username[0..len], name[0..len]);
    }

    pub fn usernameSlice(self: *const SSHEvent) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.username, 0) orelse self.username.len;
        return self.username[0..len];
    }
};

test "EventType toString" {
    try std.testing.expectEqualStrings("auth_success", EventType.auth_success.toString());
    try std.testing.expectEqualStrings("disconnect", EventType.disconnect.toString());
}

test "SSHEvent IPv4" {
    var ev = SSHEvent{};
    ev.setIPv4(192, 168, 1, 100);

    var buf: [16]u8 = undefined;
    const ip_str = try ev.formatIP(&buf);
    try std.testing.expectEqualStrings("192.168.1.100", ip_str);
}

test "SSHEvent username" {
    var ev = SSHEvent{};
    ev.setUsername("root");
    try std.testing.expectEqualStrings("root", ev.usernameSlice());
}

test "SSHEvent username truncation" {
    var ev = SSHEvent{};
    const long_name = "a" ** 100;
    ev.setUsername(long_name);
    try std.testing.expectEqual(@as(usize, 63), ev.usernameSlice().len);
}
```

`src/main.zig`:
```zig
const std = @import("std");
pub const event = @import("event.zig");

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    try stdout.print("ssh-notifier v0.1.0\n", .{});
}

test {
    _ = event;
}
```

- [ ] **Step 3: Build and run tests**

Run: `PATH=/opt/zig:$PATH zig build test`
Expected: All tests pass

Run: `PATH=/opt/zig:$PATH zig build run`
Expected: `ssh-notifier v0.1.0`

- [ ] **Step 4: Commit**

```bash
git add build.zig build.zig.zon src/main.zig src/event.zig .gitignore
git commit -m "feat: project scaffold and event model"
```

---

## Task 2: Broadcast Ring Buffer

**Files:**
- Create: `src/ring_buffer.zig`
- Modify: `src/main.zig` (add test import)

- [ ] **Step 1: Write ring buffer with tests**

`src/ring_buffer.zig`:
```zig
const std = @import("std");

pub fn BroadcastBuffer(comptime T: type) type {
    return struct {
        const Self = @This();

        items: []T,
        write_pos: std.atomic.Value(u64),
        capacity: u64,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, requested: usize) !Self {
            const cap = std.math.ceilPowerOfTwo(usize, @max(requested, 2)) catch requested;
            const items = try allocator.alloc(T, cap);
            @memset(std.mem.sliceAsBytes(items), 0);
            return .{
                .items = items,
                .write_pos = std.atomic.Value(u64).init(0),
                .capacity = @intCast(cap),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.items);
        }

        pub fn push(self: *Self, item: T) void {
            const pos = self.write_pos.load(.monotonic);
            self.items[@intCast(pos & (self.capacity - 1))] = item;
            self.write_pos.store(pos +% 1, .release);
        }

        pub fn consumer(self: *Self) Consumer {
            return .{
                .ring = self,
                .read_pos = self.write_pos.load(.acquire),
                .dropped = 0,
            };
        }

        pub const Consumer = struct {
            ring: *Self,
            read_pos: u64,
            dropped: u64,

            pub fn pop(self: *Consumer) ?T {
                const wp = self.ring.write_pos.load(.acquire);
                if (self.read_pos >= wp) return null;

                if (wp - self.read_pos > self.ring.capacity) {
                    const new_pos = wp - self.ring.capacity;
                    self.dropped += new_pos - self.read_pos;
                    self.read_pos = new_pos;
                }

                const item = self.ring.items[@intCast(self.read_pos & (self.ring.capacity - 1))];
                self.read_pos += 1;
                return item;
            }

            pub fn drainAll(self: *Consumer, out: []T) usize {
                var count: usize = 0;
                while (count < out.len) {
                    if (self.pop()) |item| {
                        out[count] = item;
                        count += 1;
                    } else break;
                }
                return count;
            }
        };
    };
}

test "push and pop" {
    var buf = try BroadcastBuffer(u32).init(std.testing.allocator, 4);
    defer buf.deinit();

    var c = buf.consumer();
    buf.push(10);
    buf.push(20);
    buf.push(30);

    try std.testing.expectEqual(@as(?u32, 10), c.pop());
    try std.testing.expectEqual(@as(?u32, 20), c.pop());
    try std.testing.expectEqual(@as(?u32, 30), c.pop());
    try std.testing.expectEqual(@as(?u32, null), c.pop());
}

test "consumer lapping drops events" {
    var buf = try BroadcastBuffer(u32).init(std.testing.allocator, 4);
    defer buf.deinit();

    var c = buf.consumer();
    for (0..6) |i| {
        buf.push(@intCast(i));
    }

    const first = c.pop().?;
    try std.testing.expectEqual(@as(u32, 2), first);
    try std.testing.expectEqual(@as(u64, 2), c.dropped);
}

test "multiple independent consumers" {
    var buf = try BroadcastBuffer(u32).init(std.testing.allocator, 8);
    defer buf.deinit();

    var c1 = buf.consumer();
    var c2 = buf.consumer();

    buf.push(42);

    try std.testing.expectEqual(@as(?u32, 42), c1.pop());
    try std.testing.expectEqual(@as(?u32, 42), c2.pop());
    try std.testing.expectEqual(@as(?u32, null), c1.pop());
    try std.testing.expectEqual(@as(?u32, null), c2.pop());
}

test "drainAll" {
    var buf = try BroadcastBuffer(u32).init(std.testing.allocator, 8);
    defer buf.deinit();

    var c = buf.consumer();
    buf.push(1);
    buf.push(2);
    buf.push(3);

    var out: [10]u32 = undefined;
    const n = c.drainAll(&out);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u32, 1), out[0]);
    try std.testing.expectEqual(@as(u32, 2), out[1]);
    try std.testing.expectEqual(@as(u32, 3), out[2]);
}

test "power of two rounding" {
    var buf = try BroadcastBuffer(u8).init(std.testing.allocator, 5);
    defer buf.deinit();
    try std.testing.expectEqual(@as(u64, 8), buf.capacity);
}
```

- [ ] **Step 2: Add import to main.zig**

Add to `src/main.zig` test block:
```zig
test {
    _ = event;
    _ = @import("ring_buffer.zig");
}
```

- [ ] **Step 3: Run tests**

Run: `PATH=/opt/zig:$PATH zig build test`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/ring_buffer.zig src/main.zig
git commit -m "feat: broadcast ring buffer with per-consumer cursors"
```

---

## Task 3: Configuration

**Files:**
- Create: `src/config.zig`
- Create: `config/ssh-notifier.toml`
- Modify: `src/main.zig` (add test import)

- [ ] **Step 1: Write config struct with defaults and TOML parser**

`src/config.zig`:
```zig
const std = @import("std");

pub const Backend = enum {
    auto,
    ebpf,
    journal,
    logfile,
    utmp,

    pub fn fromString(s: []const u8) !Backend {
        if (std.mem.eql(u8, s, "auto")) return .auto;
        if (std.mem.eql(u8, s, "ebpf")) return .ebpf;
        if (std.mem.eql(u8, s, "journal")) return .journal;
        if (std.mem.eql(u8, s, "logfile")) return .logfile;
        if (std.mem.eql(u8, s, "utmp")) return .utmp;
        return error.InvalidValue;
    }
};

pub const Urgency = enum {
    low,
    normal,
    critical,

    pub fn fromString(s: []const u8) !Urgency {
        if (std.mem.eql(u8, s, "low")) return .low;
        if (std.mem.eql(u8, s, "normal")) return .normal;
        if (std.mem.eql(u8, s, "critical")) return .critical;
        return error.InvalidValue;
    }
};

pub const WebhookEndpoint = struct {
    url: []const u8 = "",
    timeout_seconds: u32 = 5,
    max_retries: u32 = 3,
    payload_template: ?[]const u8 = null,
};

pub const Config = struct {
    backend: Backend = .auto,
    ssh_port: u16 = 22,
    auth_timeout_seconds: u32 = 30,

    notify_on_connection: bool = false,
    notify_on_auth_success: bool = true,
    notify_on_auth_failure: bool = true,
    notify_on_disconnect: bool = false,

    desktop_enabled: bool = true,
    urgency_connection: Urgency = .low,
    urgency_success: Urgency = .normal,
    urgency_failure: Urgency = .critical,
    urgency_disconnect: Urgency = .low,
    title_template: []const u8 = "SSH {event_type}",
    body_template: []const u8 = "{username}@{source_ip}:{source_port}",

    log_enabled: bool = false,
    log_path: []const u8 = "/var/log/ssh-notifier.log",

    webhook_enabled: bool = false,
    endpoints: []WebhookEndpoint = &.{},

    allocator: ?std.mem.Allocator = null,

    pub fn deinit(self: *Config) void {
        if (self.allocator) |alloc| {
            if (self.endpoints.len > 0) {
                alloc.free(self.endpoints);
            }
        }
    }
};

const Section = enum { root, detection, events, desktop, log, webhook, webhook_endpoint };

pub const ParseError = error{
    InvalidValue,
    InvalidSection,
    InvalidFormat,
    Overflow,
    InvalidCharacter,
    OutOfMemory,
};

pub fn parse(allocator: std.mem.Allocator, content: []const u8) ParseError!Config {
    var config = Config{};
    config.allocator = allocator;
    var section: Section = .root;
    var endpoints = std.ArrayList(WebhookEndpoint).init(allocator);

    var line_iter = std.mem.splitScalar(u8, content, '\n');
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        if (std.mem.startsWith(u8, line, "[[")) {
            const end = std.mem.indexOf(u8, line, "]]") orelse return error.InvalidSection;
            const name = std.mem.trim(u8, line[2..end], " ");
            if (std.mem.eql(u8, name, "webhook.endpoints")) {
                try endpoints.append(.{});
                section = .webhook_endpoint;
            } else return error.InvalidSection;
        } else if (line[0] == '[') {
            const end = std.mem.indexOfScalar(u8, line, ']') orelse return error.InvalidSection;
            const name = std.mem.trim(u8, line[1..end], " ");
            if (std.mem.eql(u8, name, "detection")) section = .detection
            else if (std.mem.eql(u8, name, "events")) section = .events
            else if (std.mem.eql(u8, name, "desktop")) section = .desktop
            else if (std.mem.eql(u8, name, "log")) section = .log
            else if (std.mem.eql(u8, name, "webhook")) section = .webhook
            else return error.InvalidSection;
        } else {
            const eq_pos = std.mem.indexOfScalar(u8, line, '=') orelse return error.InvalidFormat;
            const key = std.mem.trim(u8, line[0..eq_pos], " \t");
            const raw_val = std.mem.trim(u8, line[eq_pos + 1 ..], " \t");
            const val = stripQuotes(raw_val);
            try applyValue(&config, section, &endpoints, key, val);
        }
    }

    if (endpoints.items.len > 0) {
        config.endpoints = try endpoints.toOwnedSlice();
    } else {
        endpoints.deinit();
    }
    return config;
}

fn applyValue(config: *Config, section: Section, endpoints: *std.ArrayList(WebhookEndpoint), key: []const u8, val: []const u8) ParseError!void {
    switch (section) {
        .detection => {
            if (eq(key, "backend")) config.backend = try Backend.fromString(val)
            else if (eq(key, "ssh_port")) config.ssh_port = try std.fmt.parseInt(u16, val, 10)
            else if (eq(key, "auth_timeout_seconds")) config.auth_timeout_seconds = try std.fmt.parseInt(u32, val, 10);
        },
        .events => {
            if (eq(key, "notify_on_connection")) config.notify_on_connection = parseBool(val)
            else if (eq(key, "notify_on_auth_success")) config.notify_on_auth_success = parseBool(val)
            else if (eq(key, "notify_on_auth_failure")) config.notify_on_auth_failure = parseBool(val)
            else if (eq(key, "notify_on_disconnect")) config.notify_on_disconnect = parseBool(val);
        },
        .desktop => {
            if (eq(key, "enabled")) config.desktop_enabled = parseBool(val)
            else if (eq(key, "urgency_connection")) config.urgency_connection = try Urgency.fromString(val)
            else if (eq(key, "urgency_success")) config.urgency_success = try Urgency.fromString(val)
            else if (eq(key, "urgency_failure")) config.urgency_failure = try Urgency.fromString(val)
            else if (eq(key, "urgency_disconnect")) config.urgency_disconnect = try Urgency.fromString(val)
            else if (eq(key, "title_template")) config.title_template = val
            else if (eq(key, "body_template")) config.body_template = val;
        },
        .log => {
            if (eq(key, "enabled")) config.log_enabled = parseBool(val)
            else if (eq(key, "path")) config.log_path = val;
        },
        .webhook => {
            if (eq(key, "enabled")) config.webhook_enabled = parseBool(val);
        },
        .webhook_endpoint => {
            if (endpoints.items.len == 0) return;
            const ep = &endpoints.items[endpoints.items.len - 1];
            if (eq(key, "url")) ep.url = val
            else if (eq(key, "timeout_seconds")) ep.timeout_seconds = try std.fmt.parseInt(u32, val, 10)
            else if (eq(key, "max_retries")) ep.max_retries = try std.fmt.parseInt(u32, val, 10)
            else if (eq(key, "payload_template")) ep.payload_template = val;
        },
        .root => {},
    }
}

fn stripQuotes(s: []const u8) []const u8 {
    if (s.len >= 2 and ((s[0] == '"' and s[s.len - 1] == '"') or (s[0] == '\'' and s[s.len - 1] == '\'')))
        return s[1 .. s.len - 1];
    return s;
}

fn parseBool(s: []const u8) bool { return std.mem.eql(u8, s, "true"); }

fn eq(a: []const u8, b: []const u8) bool { return std.mem.eql(u8, a, b); }

pub fn loadFile(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 1024 * 1024);
}

pub fn mergeConfigs(base: Config, over: Config) Config {
    var m = base;
    m.notify_on_connection = over.notify_on_connection;
    m.notify_on_auth_success = over.notify_on_auth_success;
    m.notify_on_auth_failure = over.notify_on_auth_failure;
    m.notify_on_disconnect = over.notify_on_disconnect;
    m.desktop_enabled = over.desktop_enabled;
    m.urgency_connection = over.urgency_connection;
    m.urgency_success = over.urgency_success;
    m.urgency_failure = over.urgency_failure;
    m.urgency_disconnect = over.urgency_disconnect;
    m.title_template = over.title_template;
    m.body_template = over.body_template;
    m.log_enabled = over.log_enabled;
    m.webhook_enabled = over.webhook_enabled;
    if (over.backend != .auto) m.backend = over.backend;
    if (over.ssh_port != 22) m.ssh_port = over.ssh_port;
    if (over.auth_timeout_seconds != 30) m.auth_timeout_seconds = over.auth_timeout_seconds;
    if (!std.mem.eql(u8, over.log_path, "/var/log/ssh-notifier.log")) m.log_path = over.log_path;
    if (over.endpoints.len > 0) m.endpoints = over.endpoints;
    return m;
}

test "parse minimal config" {
    var config = try parse(std.testing.allocator,
        \\[detection]
        \\backend = "ebpf"
        \\ssh_port = 2222
        \\
        \\[events]
        \\notify_on_connection = true
    );
    defer config.deinit();
    try std.testing.expectEqual(Backend.ebpf, config.backend);
    try std.testing.expectEqual(@as(u16, 2222), config.ssh_port);
    try std.testing.expect(config.notify_on_connection);
    try std.testing.expect(config.notify_on_auth_success); // default
}

test "parse webhook endpoints" {
    var config = try parse(std.testing.allocator,
        \\[webhook]
        \\enabled = true
        \\
        \\[[webhook.endpoints]]
        \\url = "https://hooks.slack.com/test"
        \\timeout_seconds = 10
        \\
        \\[[webhook.endpoints]]
        \\url = "https://discord.com/api/webhooks/test"
    );
    defer config.deinit();
    try std.testing.expect(config.webhook_enabled);
    try std.testing.expectEqual(@as(usize, 2), config.endpoints.len);
    try std.testing.expectEqualStrings("https://hooks.slack.com/test", config.endpoints[0].url);
}

test "parse comments and empty lines" {
    var config = try parse(std.testing.allocator,
        \\# comment
        \\
        \\[detection]
        \\backend = "journal"
    );
    defer config.deinit();
    try std.testing.expectEqual(Backend.journal, config.backend);
}

test "defaults" {
    var config = try parse(std.testing.allocator, "");
    defer config.deinit();
    try std.testing.expectEqual(Backend.auto, config.backend);
    try std.testing.expectEqual(@as(u16, 22), config.ssh_port);
    try std.testing.expect(config.notify_on_auth_success);
    try std.testing.expect(!config.notify_on_connection);
    try std.testing.expect(config.desktop_enabled);
    try std.testing.expect(!config.log_enabled);
}
```

- [ ] **Step 2: Create example config file**

`config/ssh-notifier.toml`:
```toml
# SSH Notifier configuration
# System-wide: /etc/ssh-notifier/config.toml
# Per-user:    ~/.config/ssh-notifier/config.toml

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
urgency_connection = "low"
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

# [[webhook.endpoints]]
# url = "https://hooks.slack.com/services/..."
# timeout_seconds = 5
# max_retries = 3
# payload_template = '{"text": "SSH {event_type}: {username} from {source_ip}"}'
```

- [ ] **Step 3: Add import, run tests**

Add `_ = @import("config.zig");` to main.zig test block.

Run: `PATH=/opt/zig:$PATH zig build test`
Expected: All tests pass

- [ ] **Step 4: Commit**

```bash
git add src/config.zig config/ssh-notifier.toml src/main.zig
git commit -m "feat: TOML config parser with layered merge"
```

---

## Task 4: Template Engine

**Files:**
- Create: `src/template.zig`
- Modify: `src/main.zig` (add test import)

- [ ] **Step 1: Write template engine with tests**

`src/template.zig`:
```zig
const std = @import("std");
const SSHEvent = @import("event.zig").SSHEvent;

pub fn expand(template_str: []const u8, ev: *const SSHEvent, buf: []u8) ![]const u8 {
    var stream = std.io.fixedBufferStream(buf);
    const writer = stream.writer();
    var i: usize = 0;

    while (i < template_str.len) {
        if (template_str[i] == '{') {
            const end = std.mem.indexOfScalarPos(u8, template_str, i + 1, '}') orelse return error.NoSpaceLeft;
            const var_name = template_str[i + 1 .. end];
            try writeVar(writer, var_name, ev);
            i = end + 1;
        } else {
            try writer.writeByte(template_str[i]);
            i += 1;
        }
    }
    return stream.getWritten();
}

fn writeVar(writer: anytype, name: []const u8, ev: *const SSHEvent) !void {
    if (std.mem.eql(u8, name, "event_type")) {
        try writer.writeAll(ev.event_type.toString());
    } else if (std.mem.eql(u8, name, "username")) {
        try writer.writeAll(ev.usernameSlice());
    } else if (std.mem.eql(u8, name, "source_ip")) {
        var ip_buf: [46]u8 = undefined;
        const ip_str = try ev.formatIP(&ip_buf);
        try writer.writeAll(ip_str);
    } else if (std.mem.eql(u8, name, "source_port")) {
        try writer.print("{d}", .{ev.source_port});
    } else if (std.mem.eql(u8, name, "timestamp")) {
        try writer.print("{d}", .{ev.timestamp});
    } else if (std.mem.eql(u8, name, "session_id")) {
        try writer.print("{d}", .{ev.session_id});
    } else if (std.mem.eql(u8, name, "pid")) {
        try writer.print("{d}", .{ev.pid});
    } else {
        try writer.writeByte('{');
        try writer.writeAll(name);
        try writer.writeByte('}');
    }
}

test "expand basic template" {
    var ev = SSHEvent{};
    ev.setUsername("root");
    ev.setIPv4(10, 0, 0, 1);
    ev.source_port = 54321;
    ev.event_type = .auth_success;

    var buf: [256]u8 = undefined;
    const result = try expand("{username}@{source_ip}:{source_port}", &ev, &buf);
    try std.testing.expectEqualStrings("root@10.0.0.1:54321", result);
}

test "expand event_type" {
    var ev = SSHEvent{};
    ev.event_type = .auth_failure;
    var buf: [256]u8 = undefined;
    const result = try expand("SSH {event_type}", &ev, &buf);
    try std.testing.expectEqualStrings("SSH auth_failure", result);
}

test "expand literal text" {
    var ev = SSHEvent{};
    var buf: [256]u8 = undefined;
    const result = try expand("Hello world", &ev, &buf);
    try std.testing.expectEqualStrings("Hello world", result);
}

test "expand unknown var passed through" {
    var ev = SSHEvent{};
    var buf: [256]u8 = undefined;
    const result = try expand("{unknown}", &ev, &buf);
    try std.testing.expectEqualStrings("{unknown}", result);
}
```

- [ ] **Step 2: Add import, run tests, commit**

Add `_ = @import("template.zig");` to main.zig test block.

Run: `PATH=/opt/zig:$PATH zig build test`
Expected: All tests pass

```bash
git add src/template.zig src/main.zig
git commit -m "feat: template engine for notification formatting"
```

---

## Task 5: Log Pattern Matcher & Logfile Backend

**Files:**
- Create: `src/detect/patterns.zig`
- Create: `src/detect/logfile.zig`
- Create: `src/detect/backend.zig`
- Modify: `src/main.zig` (add test imports)

- [ ] **Step 1: Write sshd log pattern matcher with tests**

`src/detect/patterns.zig`:
```zig
const std = @import("std");
const EventType = @import("../event.zig").EventType;

pub const ParseResult = struct {
    event_type: EventType,
    username: []const u8,
    ip: []const u8,
    port: ?[]const u8,
    pid: ?u32,
};

pub fn parseLine(line: []const u8) ?ParseResult {
    if (indexOf(line, "Accepted ")) |_| return parseAccepted(line)
    else if (indexOf(line, "Failed password for ")) |_| return parseFailed(line)
    else if (indexOf(line, "Disconnected from user ")) |_| return parseDisconnectedUser(line)
    else if (indexOf(line, "Connection closed by ")) |_| return parseConnectionClosed(line)
    else if (indexOf(line, "Connection reset by ")) |_| return parseConnectionClosed(line);
    return null;
}

fn parseAccepted(line: []const u8) ?ParseResult {
    const for_pos = indexOf(line, " for ") orelse return null;
    const from_pos = indexOfFrom(line, for_pos, " from ") orelse return null;
    const port_pos = indexOfFrom(line, from_pos, " port ") orelse return null;
    const after_port = line[port_pos + 6 ..];
    const port_end = indexOf(after_port, " ") orelse after_port.len;
    return .{
        .event_type = .auth_success,
        .username = line[for_pos + 5 .. from_pos],
        .ip = line[from_pos + 6 .. port_pos],
        .port = after_port[0..port_end],
        .pid = extractPid(line),
    };
}

fn parseFailed(line: []const u8) ?ParseResult {
    const for_pos = indexOf(line, "Failed password for ") orelse return null;
    var user_start = for_pos + 20;
    if (std.mem.startsWith(u8, line[user_start..], "invalid user ")) user_start += 13;
    const from_pos = indexOfFrom(line, user_start, " from ") orelse return null;
    const port_pos = indexOfFrom(line, from_pos, " port ") orelse return null;
    const after_port = line[port_pos + 6 ..];
    const port_end = indexOf(after_port, " ") orelse after_port.len;
    return .{
        .event_type = .auth_failure,
        .username = line[user_start..from_pos],
        .ip = line[from_pos + 6 .. port_pos],
        .port = after_port[0..port_end],
        .pid = extractPid(line),
    };
}

fn parseDisconnectedUser(line: []const u8) ?ParseResult {
    const marker = "Disconnected from user ";
    const start = indexOf(line, marker) orelse return null;
    const rest = line[start + marker.len ..];
    const port_pos = indexOf(rest, " port ") orelse return null;
    const user_ip = rest[0..port_pos];
    const last_space = std.mem.lastIndexOfScalar(u8, user_ip, ' ') orelse return null;
    const after_port = rest[port_pos + 6 ..];
    const port_end = indexOf(after_port, " ") orelse after_port.len;
    return .{
        .event_type = .disconnect,
        .username = user_ip[0..last_space],
        .ip = user_ip[last_space + 1 ..],
        .port = after_port[0..port_end],
        .pid = extractPid(line),
    };
}

fn parseConnectionClosed(line: []const u8) ?ParseResult {
    const by_pos = indexOf(line, " by ") orelse return null;
    const rest = line[by_pos + 4 ..];
    const port_pos = indexOf(rest, " port ") orelse return null;
    const after_port = rest[port_pos + 6 ..];
    const port_end = indexOf(after_port, " ") orelse after_port.len;
    return .{
        .event_type = .disconnect,
        .username = "",
        .ip = rest[0..port_pos],
        .port = after_port[0..port_end],
        .pid = extractPid(line),
    };
}

fn extractPid(line: []const u8) ?u32 {
    const bracket_open = indexOf(line, "sshd[") orelse return null;
    const pid_start = bracket_open + 5;
    const bracket_close = indexOfFrom(line, pid_start, "]") orelse return null;
    return std.fmt.parseInt(u32, line[pid_start..bracket_close], 10) catch null;
}

fn indexOf(haystack: []const u8, needle: []const u8) ?usize {
    return std.mem.indexOf(u8, haystack, needle);
}

fn indexOfFrom(haystack: []const u8, start: usize, needle: []const u8) ?usize {
    if (start >= haystack.len) return null;
    const pos = std.mem.indexOf(u8, haystack[start..], needle) orelse return null;
    return pos + start;
}

test "parse accepted password" {
    const r = parseLine("Apr 14 12:00:00 host sshd[1234]: Accepted password for root from 192.168.1.1 port 54321 ssh2").?;
    try std.testing.expectEqual(EventType.auth_success, r.event_type);
    try std.testing.expectEqualStrings("root", r.username);
    try std.testing.expectEqualStrings("192.168.1.1", r.ip);
    try std.testing.expectEqualStrings("54321", r.port.?);
    try std.testing.expectEqual(@as(?u32, 1234), r.pid);
}

test "parse failed password" {
    const r = parseLine("sshd[9999]: Failed password for root from 10.0.0.1 port 22222 ssh2").?;
    try std.testing.expectEqual(EventType.auth_failure, r.event_type);
    try std.testing.expectEqualStrings("root", r.username);
}

test "parse failed invalid user" {
    const r = parseLine("sshd[9999]: Failed password for invalid user nobody from 10.0.0.1 port 22222 ssh2").?;
    try std.testing.expectEqualStrings("nobody", r.username);
}

test "parse disconnected from user" {
    const r = parseLine("sshd[1111]: Disconnected from user root 192.168.1.1 port 54321").?;
    try std.testing.expectEqual(EventType.disconnect, r.event_type);
    try std.testing.expectEqualStrings("root", r.username);
}

test "parse connection closed" {
    const r = parseLine("sshd[2222]: Connection closed by 10.0.0.1 port 12345").?;
    try std.testing.expectEqual(EventType.disconnect, r.event_type);
}

test "unrecognized returns null" {
    try std.testing.expectEqual(@as(?ParseResult, null), parseLine("Starting session: shell on pts/0"));
}
```

- [ ] **Step 2: Write backend interface**

`src/detect/backend.zig`:
```zig
const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const BroadcastBuffer = @import("../ring_buffer.zig").BroadcastBuffer;
const Config = @import("../config.zig").Config;

pub const Context = struct {
    ring: *BroadcastBuffer(SSHEvent),
    config: *const Config,
    should_stop: *std.atomic.Value(bool),

    pub fn emit(self: *Context, ev: SSHEvent) void {
        self.ring.push(ev);
    }

    pub fn stopped(self: *Context) bool {
        return self.should_stop.load(.acquire);
    }
};

pub const BackendType = enum { ebpf, journal, logfile, utmp };

pub fn probe(config: *const Config) ?BackendType {
    const req = config.backend;
    if (req == .ebpf or req == .auto) { if (checkPath("/sys/kernel/btf/vmlinux")) return .ebpf; if (req == .ebpf) return null; }
    if (req == .journal or req == .auto) { if (checkPath("/run/systemd/system")) return .journal; if (req == .journal) return null; }
    if (req == .logfile or req == .auto) { if (checkPath("/var/log/auth.log") or checkPath("/var/log/secure")) return .logfile; if (req == .logfile) return null; }
    if (req == .utmp or req == .auto) return .utmp;
    return null;
}

fn checkPath(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

test "probe returns something on this system" {
    const config = Config{};
    try std.testing.expect(probe(&config) != null);
}
```

- [ ] **Step 3: Write logfile detection backend**

`src/detect/logfile.zig`:
```zig
const std = @import("std");
const posix = std.posix;
const SSHEvent = @import("../event.zig").SSHEvent;
const Context = @import("backend.zig").Context;
const patterns = @import("patterns.zig");

const log_paths = [_][]const u8{ "/var/log/auth.log", "/var/log/secure" };

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| {
        std.log.err("logfile backend: {}", .{err});
    };
}

fn runImpl(ctx: *Context) !void {
    var log_path: []const u8 = undefined;
    for (log_paths) |p| {
        std.fs.accessAbsolute(p, .{}) catch continue;
        log_path = p;
        break;
    } else return error.FileNotFound;

    const file = try std.fs.openFileAbsolute(log_path, .{});
    defer file.close();
    const stat = try file.stat();
    try file.seekTo(stat.size);

    const ifd = try posix.inotify_init1(.{ .CLOEXEC = true, .NONBLOCK = true });
    defer posix.close(ifd);
    _ = try posix.inotify_add_watch(ifd, log_path, .{ .MODIFY = true });

    var line_buf: [4096]u8 = undefined;
    var line_len: usize = 0;
    var read_buf: [4096]u8 = undefined;
    var pollfds = [_]posix.pollfd{.{ .fd = ifd, .events = posix.POLL.IN, .revents = 0 }};

    while (!ctx.stopped()) {
        const ready = posix.poll(&pollfds, 1000) catch 0;
        if (ready == 0) continue;
        _ = posix.read(ifd, &read_buf) catch 0;

        while (true) {
            const n = file.read(&read_buf) catch break;
            if (n == 0) break;
            for (read_buf[0..n]) |byte| {
                if (byte == '\n') {
                    if (line_len > 0) { processLine(ctx, line_buf[0..line_len]); line_len = 0; }
                } else if (line_len < line_buf.len) { line_buf[line_len] = byte; line_len += 1; }
            }
        }
    }
}

fn processLine(ctx: *Context, line: []const u8) void {
    const result = patterns.parseLine(line) orelse return;
    var ev = SSHEvent{};
    ev.timestamp = @intCast(@as(u128, @bitCast(std.time.nanoTimestamp())));
    ev.event_type = result.event_type;
    ev.setUsername(result.username);
    if (result.pid) |pid| ev.pid = pid;
    if (result.port) |ps| ev.source_port = std.fmt.parseInt(u16, ps, 10) catch 0;
    parseIPInto(result.ip, &ev.source_ip);
    ev.session_id = ev.pid;
    ctx.emit(ev);
}

pub fn parseIPInto(ip_str: []const u8, out: *[16]u8) void {
    out.* = [_]u8{0} ** 16;
    out[10] = 0xff;
    out[11] = 0xff;
    var octets: [4]u8 = .{ 0, 0, 0, 0 };
    var idx: usize = 0;
    var cur: u16 = 0;
    for (ip_str) |ch| {
        if (ch == '.') { if (idx < 4) { octets[idx] = @intCast(cur); idx += 1; cur = 0; } }
        else if (ch >= '0' and ch <= '9') { cur = cur * 10 + (ch - '0'); }
    }
    if (idx < 4) octets[idx] = @intCast(cur);
    out[12] = octets[0]; out[13] = octets[1]; out[14] = octets[2]; out[15] = octets[3];
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

- [ ] **Step 4: Add imports, run tests, commit**

Add to main.zig test block:
```zig
    _ = @import("detect/patterns.zig");
    _ = @import("detect/backend.zig");
    _ = @import("detect/logfile.zig");
```

Run: `PATH=/opt/zig:$PATH zig build test`
Expected: All tests pass

```bash
git add src/detect/patterns.zig src/detect/backend.zig src/detect/logfile.zig src/main.zig
git commit -m "feat: log pattern matcher and logfile detection backend"
```

---

## Task 6: Log Writer Sink

**Files:**
- Create: `src/notify/sink.zig`
- Create: `src/notify/logwriter.zig`
- Modify: `src/main.zig`

- [ ] **Step 1: Write sink interface and log writer**

`src/notify/sink.zig`:
```zig
const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const EventType = @import("../event.zig").EventType;
const Config = @import("../config.zig").Config;
const BroadcastBuffer = @import("../ring_buffer.zig").BroadcastBuffer;

pub const SinkContext = struct {
    consumer: BroadcastBuffer(SSHEvent).Consumer,
    config: *const Config,
    should_stop: *std.atomic.Value(bool),

    pub fn stopped(self: *SinkContext) bool {
        return self.should_stop.load(.acquire);
    }
};

pub fn shouldNotify(config: *const Config, event_type: EventType) bool {
    return switch (event_type) {
        .connection => config.notify_on_connection,
        .auth_success => config.notify_on_auth_success,
        .auth_failure => config.notify_on_auth_failure,
        .disconnect => config.notify_on_disconnect,
    };
}

test "shouldNotify" {
    var config = Config{};
    try std.testing.expect(!shouldNotify(&config, .connection));
    try std.testing.expect(shouldNotify(&config, .auth_success));
    try std.testing.expect(shouldNotify(&config, .auth_failure));
    try std.testing.expect(!shouldNotify(&config, .disconnect));
}
```

`src/notify/logwriter.zig`:
```zig
const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const sink = @import("sink.zig");

pub fn run(ctx: *sink.SinkContext) void {
    runImpl(ctx) catch |err| { std.log.err("logwriter: {}", .{err}); };
}

fn runImpl(ctx: *sink.SinkContext) !void {
    const file = try std.fs.createFileAbsolute(ctx.config.log_path, .{ .truncate = false });
    defer file.close();
    try file.seekFromEnd(0);

    while (!ctx.stopped()) {
        if (ctx.consumer.pop()) |ev| {
            if (!sink.shouldNotify(ctx.config, ev.event_type)) continue;
            writeEvent(file.writer(), &ev) catch |err| { std.log.err("logwriter write: {}", .{err}); continue; };
        } else {
            std.time.sleep(50 * std.time.ns_per_ms);
        }
    }
}

pub fn writeEvent(writer: anytype, ev: *const SSHEvent) !void {
    var ip_buf: [46]u8 = undefined;
    const ip_str = ev.formatIP(&ip_buf) catch "unknown";
    try writer.print(
        "{{\"timestamp\":{d},\"event_type\":\"{s}\",\"source_ip\":\"{s}\",\"source_port\":{d},\"username\":\"{s}\",\"pid\":{d},\"session_id\":{d}}}\n",
        .{ ev.timestamp, ev.event_type.toString(), ip_str, ev.source_port, ev.usernameSlice(), ev.pid, ev.session_id },
    );
}

test "writeEvent JSON" {
    var ev = SSHEvent{};
    ev.timestamp = 1000;
    ev.event_type = .auth_success;
    ev.setIPv4(10, 0, 0, 1);
    ev.source_port = 54321;
    ev.setUsername("root");
    ev.pid = 1234;

    var buf: [512]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try writeEvent(stream.writer(), &ev);
    const out = stream.getWritten();
    try std.testing.expect(std.mem.indexOf(u8, out, "\"event_type\":\"auth_success\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"username\":\"root\"") != null);
    try std.testing.expectEqual(@as(u8, '\n'), out[out.len - 1]);
}
```

- [ ] **Step 2: Add imports, run tests, commit**

Add to main.zig test block: `_ = @import("notify/sink.zig"); _ = @import("notify/logwriter.zig");`

Run: `PATH=/opt/zig:$PATH zig build test`

```bash
git add src/notify/sink.zig src/notify/logwriter.zig src/main.zig
git commit -m "feat: sink interface and JSON log writer"
```

---

## Task 7: Main Daemon Wire-up (Checkpoint 1)

**Files:**
- Modify: `src/main.zig` (full rewrite - startup, signal handling, main loop)

After this task: daemon tails auth logs and writes JSON events to a log file.

- [ ] **Step 1: Rewrite main.zig with daemon startup**

`src/main.zig` - replace contents:
```zig
const std = @import("std");
const posix = std.posix;
pub const event = @import("event.zig");
const ring_buffer = @import("ring_buffer.zig");
const BroadcastBuffer = ring_buffer.BroadcastBuffer;
const SSHEvent = event.SSHEvent;
const config_mod = @import("config.zig");
const Config = config_mod.Config;
const backend_mod = @import("detect/backend.zig");
const logfile = @import("detect/logfile.zig");
const logwriter = @import("notify/logwriter.zig");
const sink_mod = @import("notify/sink.zig");

const VERSION = "0.1.0";
const SYSTEM_CONFIG = "/etc/ssh-notifier/config.toml";

var should_stop = std.atomic.Value(bool).init(false);
var should_reload = std.atomic.Value(bool).init(false);

fn handleSignal(sig: i32) callconv(.c) void {
    switch (sig) {
        posix.SIG.TERM, posix.SIG.INT => should_stop.store(true, .release),
        posix.SIG.HUP => should_reload.store(true, .release),
        else => {},
    }
}

fn setupSignals() void {
    const handler: posix.Sigaction.handler_fn = &handleSignal;
    const sa = posix.Sigaction{
        .handler = .{ .handler = handler },
        .mask = posix.empty_sigset,
        .flags = .{ .RESTART = true },
    };
    posix.sigaction(posix.SIG.TERM, &sa, null);
    posix.sigaction(posix.SIG.INT, &sa, null);
    posix.sigaction(posix.SIG.HUP, &sa, null);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();
    const stderr = std.io.getStdErr().writer();

    try stderr.print("ssh-notifier v{s} starting\n", .{VERSION});

    var config = loadConfig(allocator) catch |err| {
        try stderr.print("config error: {}\n", .{err});
        return err;
    };
    defer config.deinit();

    try stderr.print("config: backend={s} desktop={} log={} webhook={}\n", .{
        @tagName(config.backend), config.desktop_enabled, config.log_enabled, config.webhook_enabled,
    });

    setupSignals();

    var ring = try BroadcastBuffer(SSHEvent).init(allocator, 1024);
    defer ring.deinit();

    const backend_type = backend_mod.probe(&config) orelse {
        try stderr.print("error: no detection backend available\n", .{});
        return error.Unexpected;
    };
    try stderr.print("backend: {s}\n", .{@tagName(backend_type)});

    var detect_ctx = backend_mod.Context{
        .ring = &ring, .config = &config, .should_stop = &should_stop,
    };
    const detect_thread = try std.Thread.spawn(.{}, runBackend, .{ backend_type, &detect_ctx });

    var log_ctx: ?sink_mod.SinkContext = null;
    var log_thread: ?std.Thread = null;
    if (config.log_enabled) {
        log_ctx = .{ .consumer = ring.consumer(), .config = &config, .should_stop = &should_stop };
        log_thread = try std.Thread.spawn(.{}, logwriter.run, .{&log_ctx.?});
        try stderr.print("log sink: {s}\n", .{config.log_path});
    }

    try stderr.print("ssh-notifier running\n", .{});

    while (!should_stop.load(.acquire)) {
        if (should_reload.load(.acquire)) {
            try stderr.print("config reload (SIGHUP)\n", .{});
            should_reload.store(false, .release);
        }
        std.time.sleep(500 * std.time.ns_per_ms);
    }

    try stderr.print("shutting down\n", .{});
    if (log_thread) |t| t.join();
    detect_thread.join();
    try stderr.print("ssh-notifier stopped\n", .{});
}

fn runBackend(backend_type: backend_mod.BackendType, ctx: *backend_mod.Context) void {
    switch (backend_type) {
        .logfile => logfile.run(ctx),
        else => std.log.err("backend {s} not yet implemented", .{@tagName(backend_type)}),
    }
}

fn loadConfig(allocator: std.mem.Allocator) !Config {
    var sys_config: ?Config = null;
    if (config_mod.loadFile(allocator, SYSTEM_CONFIG)) |content| {
        defer allocator.free(content);
        sys_config = try config_mod.parse(allocator, content);
    } else |_| {}

    const home = std.posix.getenv("HOME") orelse return sys_config orelse Config{};
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const user_path = std.fmt.bufPrint(&path_buf, "{s}/.config/ssh-notifier/config.toml", .{home}) catch
        return sys_config orelse Config{};

    if (config_mod.loadFile(allocator, user_path)) |content| {
        defer allocator.free(content);
        const user_config = try config_mod.parse(allocator, content);
        if (sys_config) |sys| return config_mod.mergeConfigs(sys, user_config);
        return user_config;
    } else |_| {}

    return sys_config orelse Config{};
}

test {
    _ = event;
    _ = @import("ring_buffer.zig");
    _ = @import("config.zig");
    _ = @import("template.zig");
    _ = @import("detect/patterns.zig");
    _ = @import("detect/backend.zig");
    _ = @import("detect/logfile.zig");
    _ = @import("notify/sink.zig");
    _ = @import("notify/logwriter.zig");
}
```

- [ ] **Step 2: Build and smoke test**

Run: `PATH=/opt/zig:$PATH zig build test && zig build`
Expected: All tests pass, binary at `zig-out/bin/ssh-notifier`

- [ ] **Step 3: Commit**

```bash
git add src/main.zig
git commit -m "feat: main daemon with logfile backend and log sink"
```

---

## Task 8: D-Bus Client & Desktop Notification Sink

**Files:**
- Create: `src/dbus.zig`
- Create: `src/notify/desktop.zig`
- Modify: `src/main.zig` (add desktop sink thread)

- [ ] **Step 1: Write minimal D-Bus wire protocol client**

`src/dbus.zig`:
```zig
const std = @import("std");
const posix = std.posix;
const net = std.net;

pub const Connection = struct {
    stream: net.Stream,
    serial: u32 = 1,

    pub fn connect(bus_address: []const u8) !Connection {
        const path = extractSocketPath(bus_address) orelse return error.InvalidArgument;
        const stream = try net.connectUnixSocket(path);
        var conn = Connection{ .stream = stream };
        try conn.authenticate();
        try conn.hello();
        return conn;
    }

    pub fn close(self: *Connection) void {
        self.stream.close();
    }

    fn authenticate(self: *Connection) !void {
        _ = try self.stream.write(&[_]u8{0});
        const uid = std.os.linux.getuid();
        var uid_buf: [32]u8 = undefined;
        const uid_str = try std.fmt.bufPrint(&uid_buf, "{d}", .{uid});
        var hex_buf: [64]u8 = undefined;
        var hex_len: usize = 0;
        for (uid_str) |byte| {
            const hex = std.fmt.bytesToHex([_]u8{byte}, .lower);
            hex_buf[hex_len] = hex[0];
            hex_buf[hex_len + 1] = hex[1];
            hex_len += 2;
        }
        var auth_buf: [128]u8 = undefined;
        const auth_msg = try std.fmt.bufPrint(&auth_buf, "AUTH EXTERNAL {s}\r\n", .{hex_buf[0..hex_len]});
        _ = try self.stream.write(auth_msg);
        var resp: [256]u8 = undefined;
        const n = try self.stream.read(&resp);
        if (n < 2 or !std.mem.startsWith(u8, resp[0..n], "OK")) return error.AuthenticationFailed;
        _ = try self.stream.write("BEGIN\r\n");
    }

    fn hello(self: *Connection) !void {
        try self.methodCall("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", "", &.{});
        var discard: [1024]u8 = undefined;
        _ = self.stream.read(&discard) catch {};
    }

    pub fn notify(self: *Connection, summary: []const u8, body: []const u8, urgency: u8) !void {
        var buf: [4096]u8 = undefined;
        var p: usize = 0;
        p += writeStr(&buf, p, "ssh-notifier");   // app_name
        p += writeU32(&buf, p, 0);                  // replaces_id
        p += writeStr(&buf, p, "dialog-warning");  // icon
        p += writeStr(&buf, p, summary);            // summary
        p += writeStr(&buf, p, body);               // body
        p += writeU32(&buf, p, 0);                  // actions (empty array)
        p = writeHints(&buf, p, urgency);           // hints
        p += writeI32(&buf, p, -1);                 // expire_timeout

        try self.methodCall(
            "org.freedesktop.Notifications", "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications", "Notify", "susssasa{sv}i", buf[0..p],
        );
        var discard: [512]u8 = undefined;
        _ = self.stream.read(&discard) catch {};
    }

    fn methodCall(self: *Connection, dest: []const u8, path: []const u8, iface: []const u8, member: []const u8, sig: []const u8, body_bytes: []const u8) !void {
        var fields: [512]u8 = undefined;
        var fp: usize = 0;
        fp += writeField(&fields, fp, 1, 'o', path);
        fp += writeField(&fields, fp, 2, 's', iface);
        fp += writeField(&fields, fp, 3, 's', member);
        fp += writeField(&fields, fp, 6, 's', dest);
        if (sig.len > 0) fp += writeFieldSig(&fields, fp, sig);

        var hdr: [16]u8 = undefined;
        hdr[0] = 'l'; hdr[1] = 1; hdr[2] = 0; hdr[3] = 1;
        @memcpy(hdr[4..8], std.mem.asBytes(&@as(u32, @intCast(body_bytes.len))));
        const serial = self.serial; self.serial += 1;
        @memcpy(hdr[8..12], std.mem.asBytes(&serial));
        @memcpy(hdr[12..16], std.mem.asBytes(&@as(u32, @intCast(fp))));

        const pad_len = align8(12 + fp) - (12 + fp);
        const zeros = [_]u8{0} ** 8;

        _ = try self.stream.write(&hdr);
        _ = try self.stream.write(fields[0..fp]);
        if (pad_len > 0) _ = try self.stream.write(zeros[0..pad_len]);
        if (body_bytes.len > 0) _ = try self.stream.write(body_bytes);
    }
};

fn writeField(buf: []u8, pos: usize, code: u8, sig_char: u8, value: []const u8) usize {
    var p = align8(pos);
    @memset(buf[pos..p], 0);
    buf[p] = code; p += 1;
    buf[p] = 1; p += 1;
    buf[p] = sig_char; p += 1;
    buf[p] = 0; p += 1;
    p = align4(p);
    @memset(buf[pos..][0 .. p - pos], 0);
    p += writeStr(buf, p, value);
    return p - pos;
}

fn writeFieldSig(buf: []u8, pos: usize, sig: []const u8) usize {
    var p = align8(pos);
    @memset(buf[pos..p], 0);
    buf[p] = 8; p += 1; buf[p] = 1; p += 1; buf[p] = 'g'; p += 1; buf[p] = 0; p += 1;
    buf[p] = @intCast(sig.len); p += 1;
    @memcpy(buf[p .. p + sig.len], sig); p += sig.len;
    buf[p] = 0; p += 1;
    return p - pos;
}

fn writeStr(buf: []u8, pos: usize, s: []const u8) usize {
    @memcpy(buf[pos .. pos + 4], std.mem.asBytes(&@as(u32, @intCast(s.len))));
    @memcpy(buf[pos + 4 .. pos + 4 + s.len], s);
    buf[pos + 4 + s.len] = 0;
    const total = align4(4 + s.len + 1);
    @memset(buf[pos + 4 + s.len + 1 .. pos + total], 0);
    return total;
}

fn writeU32(buf: []u8, pos: usize, val: u32) usize {
    @memcpy(buf[pos .. pos + 4], std.mem.asBytes(&val));
    return 4;
}

fn writeI32(buf: []u8, pos: usize, val: i32) usize {
    @memcpy(buf[pos .. pos + 4], std.mem.asBytes(&val));
    return 4;
}

fn writeHints(buf: []u8, pos: usize, urgency: u8) usize {
    var p = pos;
    const dict_start = p + 4;
    p = align8(dict_start);
    @memset(buf[dict_start..p], 0);
    p += writeStr(buf, p, "urgency");
    buf[p] = 1; p += 1; buf[p] = 'y'; p += 1; buf[p] = 0; p += 1;
    buf[p] = urgency; p += 1;
    @memcpy(buf[pos .. pos + 4], std.mem.asBytes(&@as(u32, @intCast(p - dict_start))));
    return p;
}

fn align4(v: usize) usize { return (v + 3) & ~@as(usize, 3); }
fn align8(v: usize) usize { return (v + 7) & ~@as(usize, 7); }

pub fn extractSocketPath(address: []const u8) ?[]const u8 {
    const prefix = "unix:path=";
    if (!std.mem.startsWith(u8, address, prefix)) return null;
    const rest = address[prefix.len..];
    if (std.mem.indexOfScalar(u8, rest, ',')) |comma| return rest[0..comma];
    return rest;
}

test "extractSocketPath" {
    try std.testing.expectEqualStrings("/run/user/1000/bus", extractSocketPath("unix:path=/run/user/1000/bus").?);
    try std.testing.expectEqualStrings("/run/user/1000/bus", extractSocketPath("unix:path=/run/user/1000/bus,guid=abc").?);
    try std.testing.expectEqual(@as(?[]const u8, null), extractSocketPath("tcp:host=localhost"));
}

test "align" {
    try std.testing.expectEqual(@as(usize, 8), align8(5));
    try std.testing.expectEqual(@as(usize, 8), align4(7));
}
```

- [ ] **Step 2: Write desktop notification sink**

`src/notify/desktop.zig`:
```zig
const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const EventType = @import("../event.zig").EventType;
const Config = @import("../config.zig").Config;
const Urgency = @import("../config.zig").Urgency;
const dbus = @import("../dbus.zig");
const template = @import("../template.zig");
const sink = @import("sink.zig");

pub fn run(ctx: *sink.SinkContext) void {
    while (!ctx.stopped()) {
        if (ctx.consumer.pop()) |ev| {
            if (!sink.shouldNotify(ctx.config, ev.event_type)) continue;
            sendNotification(ctx.config, &ev);
        } else {
            std.time.sleep(50 * std.time.ns_per_ms);
        }
    }
}

fn sendNotification(config: *const Config, ev: *const SSHEvent) void {
    var title_buf: [256]u8 = undefined;
    var body_buf: [512]u8 = undefined;
    const title = template.expand(config.title_template, ev, &title_buf) catch "SSH Event";
    const body = template.expand(config.body_template, ev, &body_buf) catch "unknown";
    const urgency = urgencyByte(config, ev.event_type);
    sendToSessions(title, body, urgency);
}

fn sendToSessions(title: []const u8, body: []const u8, urgency: u8) void {
    var dir = std.fs.openDirAbsolute("/run/user", .{ .iterate = true }) catch {
        notifySendFallback(title, body, urgency); return;
    };
    defer dir.close();
    var iter = dir.iterate();
    var sent = false;
    while (iter.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        var buf: [256]u8 = undefined;
        const addr = std.fmt.bufPrint(&buf, "unix:path=/run/user/{s}/bus", .{entry.name}) catch continue;
        if (sendViaDbus(addr, title, body, urgency)) sent = true;
    }
    if (!sent) notifySendFallback(title, body, urgency);
}

fn sendViaDbus(addr: []const u8, title: []const u8, body: []const u8, urgency: u8) bool {
    var conn = dbus.Connection.connect(addr) catch return false;
    defer conn.close();
    conn.notify(title, body, urgency) catch return false;
    return true;
}

fn notifySendFallback(title: []const u8, body: []const u8, urgency: u8) void {
    const u_str: []const u8 = if (urgency == 0) "low" else if (urgency == 2) "critical" else "normal";
    var child = std.process.Child.init(&.{ "notify-send", "-u", u_str, title, body }, std.heap.page_allocator);
    child.spawn() catch return;
    _ = child.wait() catch {};
}

fn urgencyByte(config: *const Config, et: EventType) u8 {
    const u = switch (et) {
        .connection => config.urgency_connection,
        .auth_success => config.urgency_success,
        .auth_failure => config.urgency_failure,
        .disconnect => config.urgency_disconnect,
    };
    return switch (u) { .low => 0, .normal => 1, .critical => 2 };
}

test "urgencyByte" {
    const config = Config{};
    try std.testing.expectEqual(@as(u8, 1), urgencyByte(&config, .auth_success));
    try std.testing.expectEqual(@as(u8, 2), urgencyByte(&config, .auth_failure));
    try std.testing.expectEqual(@as(u8, 0), urgencyByte(&config, .connection));
}
```

- [ ] **Step 3: Update main.zig - add desktop sink thread**

Add import at top: `const desktop = @import("notify/desktop.zig");`

Add after log sink startup in `main()`:
```zig
    var desktop_ctx: ?sink_mod.SinkContext = null;
    var desktop_thread: ?std.Thread = null;
    if (config.desktop_enabled) {
        desktop_ctx = .{ .consumer = ring.consumer(), .config = &config, .should_stop = &should_stop };
        desktop_thread = try std.Thread.spawn(.{}, desktop.run, .{&desktop_ctx.?});
        try stderr.print("desktop sink: enabled\n", .{});
    }
```

Add to shutdown: `if (desktop_thread) |t| t.join();`

Add to test block: `_ = @import("dbus.zig"); _ = @import("notify/desktop.zig");`

- [ ] **Step 4: Build and test**

Run: `PATH=/opt/zig:$PATH zig build test && zig build`
Expected: All tests pass, compiles

- [ ] **Step 5: Commit**

```bash
git add src/dbus.zig src/notify/desktop.zig src/main.zig
git commit -m "feat: D-Bus client and desktop notification sink"
```

---

## Task 9: Webhook Sink

**Files:**
- Create: `src/notify/webhook.zig`
- Modify: `src/main.zig`

- [ ] **Step 1: Write webhook sink**

`src/notify/webhook.zig`:
```zig
const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const WebhookEndpoint = @import("../config.zig").WebhookEndpoint;
const template = @import("../template.zig");
const sink = @import("sink.zig");

pub fn run(ctx: *sink.SinkContext) void {
    while (!ctx.stopped()) {
        if (ctx.consumer.pop()) |ev| {
            if (!sink.shouldNotify(ctx.config, ev.event_type)) continue;
            for (ctx.config.endpoints) |ep| sendWithRetry(ep, &ev);
        } else {
            std.time.sleep(50 * std.time.ns_per_ms);
        }
    }
}

fn sendWithRetry(ep: WebhookEndpoint, ev: *const SSHEvent) void {
    var delay_ms: u64 = 1000;
    for (0..ep.max_retries + 1) |attempt| {
        if (attempt > 0) std.time.sleep(delay_ms * std.time.ns_per_ms);
        delay_ms *= 2;
        if (sendOnce(ep, ev)) return;
    }
    std.log.err("webhook: retries exhausted for {s}", .{ep.url});
}

fn sendOnce(ep: WebhookEndpoint, ev: *const SSHEvent) bool {
    var payload_buf: [4096]u8 = undefined;
    const payload = buildPayload(ep, ev, &payload_buf) catch return false;
    const uri = std.Uri.parse(ep.url) catch return false;

    var client: std.http.Client = .{ .allocator = std.heap.page_allocator };
    defer client.deinit();
    var hdr_buf: [4096]u8 = undefined;
    var req = client.open(.POST, uri, .{
        .server_header_buffer = &hdr_buf,
        .extra_headers = &.{.{ .name = "Content-Type", .value = "application/json" }},
    }) catch return false;
    defer req.deinit();

    req.transfer_encoding = .{ .content_length = payload.len };
    req.send() catch return false;
    req.writeAll(payload) catch return false;
    req.finish() catch return false;
    req.wait() catch return false;
    return req.status == .ok or req.status == .no_content or req.status == .accepted;
}

fn buildPayload(ep: WebhookEndpoint, ev: *const SSHEvent, buf: []u8) ![]const u8 {
    if (ep.payload_template) |tmpl| return template.expand(tmpl, ev, buf);
    return defaultPayload(ev, buf);
}

pub fn defaultPayload(ev: *const SSHEvent, buf: []u8) ![]const u8 {
    var ip_buf: [46]u8 = undefined;
    const ip = ev.formatIP(&ip_buf) catch "unknown";
    var stream = std.io.fixedBufferStream(buf);
    try stream.writer().print(
        "{{\"timestamp\":{d},\"event_type\":\"{s}\",\"source_ip\":\"{s}\",\"source_port\":{d},\"username\":\"{s}\",\"pid\":{d},\"session_id\":{d}}}",
        .{ ev.timestamp, ev.event_type.toString(), ip, ev.source_port, ev.usernameSlice(), ev.pid, ev.session_id },
    );
    return stream.getWritten();
}

test "defaultPayload" {
    var ev = SSHEvent{};
    ev.event_type = .auth_failure;
    ev.setIPv4(1, 2, 3, 4);
    ev.setUsername("admin");
    var buf: [1024]u8 = undefined;
    const p = try defaultPayload(&ev, &buf);
    try std.testing.expect(std.mem.indexOf(u8, p, "\"auth_failure\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, p, "\"admin\"") != null);
}
```

- [ ] **Step 2: Update main.zig, build, commit**

Add import: `const webhook = @import("notify/webhook.zig");`

Add after desktop sink:
```zig
    var webhook_ctx: ?sink_mod.SinkContext = null;
    var webhook_thread: ?std.Thread = null;
    if (config.webhook_enabled and config.endpoints.len > 0) {
        webhook_ctx = .{ .consumer = ring.consumer(), .config = &config, .should_stop = &should_stop };
        webhook_thread = try std.Thread.spawn(.{}, webhook.run, .{&webhook_ctx.?});
        try stderr.print("webhook sink: {d} endpoints\n", .{config.endpoints.len});
    }
```

Shutdown: `if (webhook_thread) |t| t.join();`

Test block: `_ = @import("notify/webhook.zig");`

Run: `PATH=/opt/zig:$PATH zig build test && zig build`

```bash
git add src/notify/webhook.zig src/main.zig
git commit -m "feat: webhook sink with retry"
```

---

## Task 10: Journal Detection Backend

**Files:**
- Create: `src/detect/journal.zig`
- Modify: `build.zig` (link libsystemd)
- Modify: `src/main.zig`

- [ ] **Step 1: Write journal backend**

`src/detect/journal.zig`:
```zig
const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const Context = @import("backend.zig").Context;
const patterns = @import("patterns.zig");
const logfile = @import("logfile.zig");

const c = @cImport({ @cInclude("systemd/sd-journal.h"); });

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| { std.log.err("journal backend: {}", .{err}); };
}

fn runImpl(ctx: *Context) !void {
    var journal: ?*c.sd_journal = null;
    if (c.sd_journal_open(&journal, c.SD_JOURNAL_LOCAL_ONLY | c.SD_JOURNAL_SYSTEM) < 0) return error.Unexpected;
    defer _ = c.sd_journal_close(journal);

    if (c.sd_journal_add_match(journal, "SYSLOG_IDENTIFIER=sshd", 22) < 0) return error.Unexpected;
    if (c.sd_journal_seek_tail(journal) < 0) return error.Unexpected;
    _ = c.sd_journal_previous(journal);

    while (!ctx.stopped()) {
        const rc = c.sd_journal_wait(journal, 1000 * 1000);
        if (rc < 0 or rc == c.SD_JOURNAL_NOP) continue;

        while (c.sd_journal_next(journal) > 0) {
            var data: [*c]const u8 = undefined;
            var len: usize = 0;
            if (c.sd_journal_get_data(journal, "MESSAGE", @ptrCast(&data), &len) < 0) continue;
            const full = data[0..len];
            if (std.mem.indexOf(u8, full, "=")) |eq_pos| processMessage(ctx, full[eq_pos + 1 ..]);
        }
    }
}

fn processMessage(ctx: *Context, msg: []const u8) void {
    const result = patterns.parseLine(msg) orelse return;
    var ev = SSHEvent{};
    ev.timestamp = @intCast(@as(u128, @bitCast(std.time.nanoTimestamp())));
    ev.event_type = result.event_type;
    ev.setUsername(result.username);
    if (result.pid) |pid| ev.pid = pid;
    if (result.port) |ps| ev.source_port = std.fmt.parseInt(u16, ps, 10) catch 0;
    logfile.parseIPInto(result.ip, &ev.source_ip);
    ev.session_id = ev.pid;
    ctx.emit(ev);
}
```

- [ ] **Step 2: Update build.zig - link system libraries**

Add after `b.installArtifact(exe)`:
```zig
    exe.linkSystemLibrary("systemd");
    exe.linkLibC();
    unit_tests.linkSystemLibrary("systemd");
    unit_tests.linkLibC();
```

- [ ] **Step 3: Update main.zig dispatch**

Add import: `const journal = @import("detect/journal.zig");`

Update `runBackend`:
```zig
fn runBackend(backend_type: backend_mod.BackendType, ctx: *backend_mod.Context) void {
    switch (backend_type) {
        .logfile => logfile.run(ctx),
        .journal => journal.run(ctx),
        else => std.log.err("backend {s} not yet implemented", .{@tagName(backend_type)}),
    }
}
```

Test block: `_ = @import("detect/journal.zig");`

- [ ] **Step 4: Build and test**

Run: `PATH=/opt/zig:$PATH zig build test && zig build`

```bash
git add src/detect/journal.zig build.zig src/main.zig
git commit -m "feat: journal detection backend via sd_journal"
```

---

## Task 11: BPF Program & eBPF Detection Backend

**Files:**
- Create: `bpf/ssh_monitor.h`
- Create: `bpf/ssh_monitor.bpf.c`
- Create: `src/detect/ebpf.zig`
- Modify: `build.zig`
- Modify: `src/main.zig`

**Prerequisite:** `sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h`

- [ ] **Step 1: Create shared BPF event header**

`bpf/ssh_monitor.h`:
```c
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
    __u16 source_port;
    __u16 dest_port;
    __u32 source_ip4;
    __u8 comm[16];
} __attribute__((packed));

#endif
```

- [ ] **Step 2: Write BPF C program**

`bpf/ssh_monitor.bpf.c`:
```c
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "ssh_monitor.h"

char LICENSE[] SEC("license") = "GPL";

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 256 * 1024); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096); __type(key, __u32); __type(value, __u32); } sshd_pids SEC(".maps");

const volatile __u16 target_port = 22;

SEC("tp/sock/inet_sock_set_state")
int handle_inet_sock_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    if (ctx->protocol != IPPROTO_TCP || ctx->newstate != TCP_ESTABLISHED)
        return 0;
    if (ctx->sport != target_port)
        return 0;

    struct ssh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    e->timestamp = bpf_ktime_get_ns();
    e->event_type = SSH_EVENT_CONNECTION;
    e->pid = pid;
    e->ppid = 0;
    e->source_port = ctx->dport;
    e->dest_port = ctx->sport;
    e->source_ip4 = ctx->saddr_v4;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    /* Track this sshd PID */
    __u32 zero = 0;
    bpf_map_update_elem(&sshd_pids, &pid, &zero, BPF_ANY);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exec")
int handle_exec(struct trace_event_raw_sched_process_exec *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    __u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    if (!bpf_map_lookup_elem(&sshd_pids, &ppid))
        return 0;

    struct ssh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->event_type = SSH_EVENT_AUTH_SUCCESS;
    e->pid = pid;
    e->ppid = ppid;
    e->source_port = 0;
    e->dest_port = 0;
    e->source_ip4 = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("tp/sched/sched_process_exit")
int handle_exit(struct trace_event_raw_sched_process_template *ctx) {
    __u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&sshd_pids, &pid))
        return 0;

    struct ssh_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;

    e->timestamp = bpf_ktime_get_ns();
    e->event_type = SSH_EVENT_DISCONNECT;
    e->pid = pid;
    e->ppid = 0;
    e->source_port = 0;
    e->dest_port = 0;
    e->source_ip4 = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_ringbuf_submit(e, 0);
    bpf_map_delete_elem(&sshd_pids, &pid);
    return 0;
}
```

- [ ] **Step 3: Update build.zig - add BPF compilation and libbpf linkage**

Add BPF compilation step and libbpf linkage to `build.zig`:
```zig
    // BPF compilation
    const bpf_compile = b.addSystemCommand(&.{
        "clang", "-target", "bpf", "-D__TARGET_ARCH_x86_64",
        "-O2", "-g", "-c", "bpf/ssh_monitor.bpf.c",
        "-I", "bpf", "-o",
    });
    const bpf_obj = bpf_compile.addOutputFileArg("ssh_monitor.bpf.o");
    const install_bpf = b.addInstallFile(bpf_obj, "bpf/ssh_monitor.bpf.o");
    exe.step.dependOn(&install_bpf.step);

    exe.linkSystemLibrary("bpf");
```

Note: clang is needed for BPF target. Install with `dnf install clang`.

- [ ] **Step 4: Write eBPF detection backend**

`src/detect/ebpf.zig`:
```zig
const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const EventType = @import("../event.zig").EventType;
const Context = @import("backend.zig").Context;

const c = @cImport({ @cInclude("bpf/libbpf.h"); @cInclude("bpf/bpf.h"); });

const BpfEvent = extern struct {
    timestamp: u64, event_type: u32, pid: u32, ppid: u32,
    source_port: u16, dest_port: u16, source_ip4: u32, comm: [16]u8,
};

var global_ctx: ?*Context = null;

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| { std.log.err("ebpf backend: {}", .{err}); };
}

fn runImpl(ctx: *Context) !void {
    global_ctx = ctx;
    defer global_ctx = null;

    const obj = c.bpf_object__open("zig-out/bpf/ssh_monitor.bpf.o") orelse return error.Unexpected;
    defer c.bpf_object__close(obj);
    if (c.bpf_object__load(obj) != 0) return error.Unexpected;
    if (c.bpf_object__attach(obj) != 0) return error.Unexpected;

    const rb_map = c.bpf_object__find_map_by_name(obj, "events") orelse return error.Unexpected;
    const rb_fd = c.bpf_map__fd(rb_map);
    if (rb_fd < 0) return error.Unexpected;

    const rb = c.ring_buffer__new(rb_fd, &handleEvent, null, null) orelse return error.Unexpected;
    defer c.ring_buffer__free(rb);

    std.log.info("ebpf: attached, listening on port {d}", .{ctx.config.ssh_port});

    while (!ctx.stopped()) {
        _ = c.ring_buffer__poll(rb, 100);
    }
}

fn handleEvent(_: ?*anyopaque, data: ?*anyopaque, _: usize) callconv(.C) c_int {
    const bpf_ev: *const BpfEvent = @ptrCast(@alignCast(data orelse return 0));
    const ctx = global_ctx orelse return 0;

    var ev = SSHEvent{};
    ev.timestamp = bpf_ev.timestamp;
    ev.event_type = switch (bpf_ev.event_type) {
        0 => EventType.connection, 1 => EventType.auth_success,
        2 => EventType.auth_failure, 3 => EventType.disconnect,
        else => return 0,
    };
    ev.pid = bpf_ev.pid;
    ev.session_id = bpf_ev.pid;
    ev.source_port = bpf_ev.source_port;
    ev.source_ip = [_]u8{0} ** 16;
    ev.source_ip[10] = 0xff; ev.source_ip[11] = 0xff;
    const ip: [4]u8 = @bitCast(bpf_ev.source_ip4);
    ev.source_ip[12] = ip[0]; ev.source_ip[13] = ip[1]; ev.source_ip[14] = ip[2]; ev.source_ip[15] = ip[3];

    ctx.emit(ev);
    return 0;
}
```

- [ ] **Step 5: Update main.zig dispatch**

Add import: `const ebpf = @import("detect/ebpf.zig");`

Update `runBackend`:
```zig
fn runBackend(backend_type: backend_mod.BackendType, ctx: *backend_mod.Context) void {
    switch (backend_type) {
        .logfile => logfile.run(ctx),
        .journal => journal.run(ctx),
        .ebpf => ebpf.run(ctx),
        else => std.log.err("backend {s} not yet implemented", .{@tagName(backend_type)}),
    }
}
```

- [ ] **Step 6: Generate vmlinux.h, install clang, build**

```bash
sudo dnf install clang
sudo bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
PATH=/opt/zig:$PATH zig build
```

- [ ] **Step 7: Commit**

```bash
git add bpf/ssh_monitor.h bpf/ssh_monitor.bpf.c src/detect/ebpf.zig build.zig src/main.zig
git commit -m "feat: eBPF detection backend with CO-RE tracepoints"
```

---

## Task 12: utmp Backend & Session Correlation

**Files:**
- Create: `src/detect/utmp.zig`
- Create: `src/session.zig`
- Modify: `src/main.zig`

- [ ] **Step 1: Write session correlation table with tests**

`src/session.zig`:
```zig
const std = @import("std");
const SSHEvent = @import("event.zig").SSHEvent;
const EventType = @import("event.zig").EventType;

pub const SessionState = enum { connected, authenticated, auth_failed, disconnected };

pub const SessionEntry = struct {
    state: SessionState, source_ip: [16]u8, source_port: u16,
    username: [64]u8, pid: u32, connect_time: u64, last_activity: u64,
};

pub const SessionTable = struct {
    entries: std.AutoHashMap(u64, SessionEntry),
    max_entries: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) SessionTable {
        return .{ .entries = std.AutoHashMap(u64, SessionEntry).init(allocator), .max_entries = max_entries, .allocator = allocator };
    }
    pub fn deinit(self: *SessionTable) void { self.entries.deinit(); }

    pub fn update(self: *SessionTable, ev: *const SSHEvent) void {
        const r = self.entries.getOrPut(ev.session_id) catch return;
        if (!r.found_existing) {
            if (self.entries.count() > self.max_entries) self.evictOldest();
            r.value_ptr.* = .{ .state = .connected, .source_ip = ev.source_ip, .source_port = ev.source_port,
                .username = ev.username, .pid = ev.pid, .connect_time = ev.timestamp, .last_activity = ev.timestamp };
        }
        r.value_ptr.last_activity = ev.timestamp;
        r.value_ptr.state = switch (ev.event_type) { .connection => .connected, .auth_success => .authenticated, .auth_failure => .auth_failed, .disconnect => .disconnected };
    }

    pub fn checkTimeouts(self: *SessionTable, now: u64, timeout_ns: u64, out: []SSHEvent) usize {
        var count: usize = 0;
        var to_remove = std.ArrayList(u64).init(self.allocator);
        defer to_remove.deinit();
        var iter = self.entries.iterator();
        while (iter.next()) |e| {
            if (e.value_ptr.state == .connected and now -| e.value_ptr.connect_time > timeout_ns) {
                if (count < out.len) {
                    out[count] = .{ .timestamp = now, .event_type = .auth_failure, .source_ip = e.value_ptr.source_ip,
                        .source_port = e.value_ptr.source_port, .username = e.value_ptr.username, .pid = e.value_ptr.pid, .session_id = e.key_ptr.* };
                    count += 1;
                }
                e.value_ptr.state = .auth_failed;
            }
            if (e.value_ptr.state == .disconnected and now -| e.value_ptr.last_activity > timeout_ns * 2)
                to_remove.append(e.key_ptr.*) catch {};
        }
        for (to_remove.items) |id| _ = self.entries.remove(id);
        return count;
    }

    fn evictOldest(self: *SessionTable) void {
        var oldest: u64 = std.math.maxInt(u64);
        var key: ?u64 = null;
        var iter = self.entries.iterator();
        while (iter.next()) |e| { if (e.value_ptr.last_activity < oldest) { oldest = e.value_ptr.last_activity; key = e.key_ptr.*; } }
        if (key) |k| _ = self.entries.remove(k);
    }
};

test "session update and timeout" {
    var t = SessionTable.init(std.testing.allocator, 4096);
    defer t.deinit();
    var ev = SSHEvent{}; ev.session_id = 1; ev.event_type = .connection; ev.timestamp = 1000;
    t.update(&ev);
    try std.testing.expectEqual(SessionState.connected, t.entries.get(1).?.state);

    var out: [10]SSHEvent = undefined;
    const timeout: u64 = 30 * std.time.ns_per_s;
    const count = t.checkTimeouts(1000 + timeout + 1, timeout, &out);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(EventType.auth_failure, out[0].event_type);
}
```

- [ ] **Step 2: Write utmp backend**

`src/detect/utmp.zig`:
```zig
const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const Context = @import("backend.zig").Context;
const logfile = @import("logfile.zig");
const c = @cImport({ @cInclude("utmp.h"); });

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| { std.log.err("utmp backend: {}", .{err}); };
}

fn runImpl(ctx: *Context) !void {
    var known = std.AutoHashMap(u32, void).init(std.heap.page_allocator);
    defer known.deinit();
    scan(&known, ctx, true);
    while (!ctx.stopped()) {
        std.time.sleep(2 * std.time.ns_per_s);
        scan(&known, ctx, false);
    }
}

fn scan(known: *std.AutoHashMap(u32, void), ctx: *Context, initial: bool) void {
    const file = std.fs.openFileAbsolute("/var/run/utmp", .{}) catch return;
    defer file.close();
    var current = std.AutoHashMap(u32, void).init(std.heap.page_allocator);
    defer current.deinit();

    const sz = @sizeOf(c.struct_utmp);
    var buf: [sz]u8 align(@alignOf(c.struct_utmp)) = undefined;
    while (true) {
        const n = file.read(&buf) catch break;
        if (n < sz) break;
        const entry: *const c.struct_utmp = @ptrCast(&buf);
        if (entry.ut_type != c.USER_PROCESS) continue;
        const pid: u32 = @intCast(entry.ut_pid);
        current.put(pid, {}) catch continue;
        const host = std.mem.sliceTo(&entry.ut_host, 0);
        if (host.len == 0) continue;
        if (!known.contains(pid)) {
            known.put(pid, {}) catch continue;
            if (!initial) {
                var ev = SSHEvent{};
                ev.timestamp = @intCast(@as(u128, @bitCast(std.time.nanoTimestamp())));
                ev.event_type = .auth_success;
                ev.pid = pid; ev.session_id = pid;
                ev.setUsername(std.mem.sliceTo(&entry.ut_user, 0));
                logfile.parseIPInto(host, &ev.source_ip);
                ctx.emit(ev);
            }
        }
    }
    var iter = known.iterator();
    var to_remove = std.ArrayList(u32).init(std.heap.page_allocator);
    defer to_remove.deinit();
    while (iter.next()) |e| {
        if (!current.contains(e.key_ptr.*)) {
            if (!initial) { var ev = SSHEvent{}; ev.timestamp = @intCast(@as(u128, @bitCast(std.time.nanoTimestamp()))); ev.event_type = .disconnect; ev.pid = e.key_ptr.*; ev.session_id = e.key_ptr.*; ctx.emit(ev); }
            to_remove.append(e.key_ptr.*) catch {};
        }
    }
    for (to_remove.items) |pid| _ = known.remove(pid);
}
```

- [ ] **Step 3: Update main.zig - complete backend dispatch**

Add imports: `const ebpf = @import("detect/ebpf.zig"); const utmp_mod = @import("detect/utmp.zig");`

```zig
fn runBackend(backend_type: backend_mod.BackendType, ctx: *backend_mod.Context) void {
    switch (backend_type) {
        .logfile => logfile.run(ctx),
        .journal => journal.run(ctx),
        .ebpf => ebpf.run(ctx),
        .utmp => utmp_mod.run(ctx),
    }
}
```

Test block: `_ = @import("session.zig"); _ = @import("detect/utmp.zig");`

- [ ] **Step 4: Build and test**

Run: `PATH=/opt/zig:$PATH zig build test && zig build`

```bash
git add src/session.zig src/detect/utmp.zig src/main.zig
git commit -m "feat: utmp backend and session correlation table"
```

---

## Task 13: Systemd Integration & Service File

**Files:**
- Create: `config/ssh-notifier.service`
- Modify: `src/main.zig` (sd_notify, SIGUSR1 status)

- [ ] **Step 1: Add config live-reload to main.zig**

Add to `src/main.zig` — import session module and implement SIGHUP config reload:

```zig
const session_mod = @import("session.zig");
```

In `main()`, create a session table before the main loop:
```zig
    var sessions = session_mod.SessionTable.init(allocator, 4096);
    defer sessions.deinit();
    const timeout_ns: u64 = @as(u64, config.auth_timeout_seconds) * std.time.ns_per_s;
```

Replace the stub reload block in the main loop with actual reload + session timeout checking:
```zig
    while (!should_stop.load(.acquire)) {
        if (should_reload.load(.acquire)) {
            should_reload.store(false, .release);
            if (loadConfig(allocator)) |new_cfg| {
                config.deinit();
                config = new_cfg;
                try stderr.print("config reloaded\n", .{});
            } else |err| {
                try stderr.print("config reload failed: {}, keeping current\n", .{err});
            }
        }

        // Check session timeouts for auth_failure inference
        const now: u64 = @intCast(@as(u128, @bitCast(std.time.nanoTimestamp())));
        var timeout_events: [32]SSHEvent = undefined;
        const n = sessions.checkTimeouts(now, timeout_ns, &timeout_events);
        for (timeout_events[0..n]) |ev| ring.push(ev);

        if (should_dump.load(.acquire)) {
            should_dump.store(false, .release);
            try stderr.print("=== status: backend={s} write_pos={d} sessions={d} ===\n",
                .{ @tagName(backend_type), ring.write_pos.load(.monotonic), sessions.entries.count() });
        }

        std.time.sleep(500 * std.time.ns_per_ms);
    }
```

- [ ] **Step 2: Add sd_notify to main.zig**

Add this function to `src/main.zig`:
```zig
fn sdNotify(state: []const u8) void {
    const addr = std.posix.getenv("NOTIFY_SOCKET") orelse return;
    if (addr.len == 0) return;
    const sock = std.posix.socket(std.posix.AF.UNIX, std.posix.SOCK.DGRAM | std.posix.SOCK.CLOEXEC, 0) catch return;
    defer std.posix.close(sock);
    var sa: std.posix.sockaddr.un = .{ .path = undefined };
    @memset(&sa.path, 0);
    const src = if (addr[0] == '@') addr[1..] else addr;
    const offset: usize = if (addr[0] == '@') 1 else 0;
    const copy_len = @min(src.len, sa.path.len - offset);
    @memcpy(sa.path[offset .. offset + copy_len], src[0..copy_len]);
    if (addr[0] == '@') sa.path[0] = 0;
    _ = std.posix.sendto(sock, state, 0, @ptrCast(&sa), @sizeOf(@TypeOf(sa))) catch {};
}
```

Call `sdNotify("READY=1\n")` after "ssh-notifier running" line.
Call `sdNotify("STOPPING=1\n")` at start of shutdown.

- [ ] **Step 3: Add SIGUSR1 status dump**

Add `var should_dump = std.atomic.Value(bool).init(false);`

Update signal handler to include: `posix.SIG.USR1 => should_dump.store(true, .release),`

Register in setupSignals: `posix.sigaction(posix.SIG.USR1, &sa, null);`

Note: the SIGUSR1 dump is already wired into the main loop in Step 1's replacement code above.

- [ ] **Step 4: Create service file**

`config/ssh-notifier.service`:
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

- [ ] **Step 5: Build and integration test**

```bash
PATH=/opt/zig:$PATH zig build
sudo cp zig-out/bin/ssh-notifier /usr/bin/
sudo cp config/ssh-notifier.service /etc/systemd/system/
sudo mkdir -p /etc/ssh-notifier
sudo cp config/ssh-notifier.toml /etc/ssh-notifier/config.toml
sudo systemctl daemon-reload
sudo systemctl start ssh-notifier
sudo systemctl status ssh-notifier
sudo kill -USR1 $(pidof ssh-notifier)
sudo journalctl -u ssh-notifier -n 20
sudo systemctl stop ssh-notifier
```

- [ ] **Step 6: Commit**

```bash
git add config/ssh-notifier.service src/main.zig
git commit -m "feat: systemd integration, config reload, session timeouts"
```

---

## Checkpoints

| After Task | What Works |
|---|---|
| 7 | Daemon tails auth logs, writes JSON events to log file |
| 8 | Desktop notifications via D-Bus / notify-send |
| 9 | Webhook notifications with retry |
| 10 | Journal detection backend |
| 11 | eBPF detection with kernel tracepoints |
| 12 | utmp backend, session tracking, auth timeout inference |
| 13 | Systemd service, sd_notify, SIGUSR1 status |
