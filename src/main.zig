const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
pub const event = @import("event.zig");
const ring_buffer = @import("ring_buffer.zig");
const BroadcastBuffer = ring_buffer.BroadcastBuffer;
const SSHEvent = event.SSHEvent;
const config_mod = @import("config.zig");
const Config = config_mod.Config;
const session_mod = @import("session.zig");
const backend_mod = @import("detect/backend.zig");
const logfile = @import("detect/logfile.zig");
const journal = @import("detect/journal.zig");
const ebpf = @import("detect/ebpf.zig");
const utmp_mod = @import("detect/utmp.zig");
const logwriter = @import("notify/logwriter.zig");
const desktop = @import("notify/desktop.zig");
const webhook = @import("notify/webhook.zig");
const sink_mod = @import("notify/sink.zig");

const VERSION = "0.1.0";
const SYSTEM_CONFIG = "/etc/ssh-notifier/config.toml";

var should_stop = std.atomic.Value(bool).init(false);
var should_reload = std.atomic.Value(bool).init(false);
var should_dump = std.atomic.Value(bool).init(false);

fn handleSignal(sig: i32) callconv(.c) void {
    switch (sig) {
        posix.SIG.TERM, posix.SIG.INT => should_stop.store(true, .release),
        posix.SIG.HUP => should_reload.store(true, .release),
        posix.SIG.USR1 => should_dump.store(true, .release),
        else => {},
    }
}

fn setupSignals() void {
    const sa = posix.Sigaction{
        .handler = .{ .handler = &handleSignal },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = linux.SA.RESTART,
    };
    posix.sigaction(posix.SIG.TERM, &sa, null);
    posix.sigaction(posix.SIG.INT, &sa, null);
    posix.sigaction(posix.SIG.HUP, &sa, null);
    posix.sigaction(posix.SIG.USR1, &sa, null);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("ssh-notifier v{s} starting\n", .{VERSION});

    var config = loadConfig(allocator) catch |err| {
        std.debug.print("config error: {}\n", .{err});
        return err;
    };
    defer config.deinit();

    std.debug.print("config: backend={s} desktop={} log={} webhook={}\n", .{
        @tagName(config.backend), config.desktop_enabled, config.log_enabled, config.webhook_enabled,
    });

    setupSignals();

    var ring = try BroadcastBuffer(SSHEvent).init(allocator, 1024);
    defer ring.deinit();

    const backend_type = backend_mod.probe(&config) orelse {
        std.debug.print("error: no detection backend available\n", .{});
        return error.Unexpected;
    };
    std.debug.print("backend: {s}\n", .{@tagName(backend_type)});

    var detect_ctx = backend_mod.Context{
        .ring = &ring,
        .config = &config,
        .should_stop = &should_stop,
    };
    const detect_thread = try std.Thread.spawn(.{}, runBackend, .{ backend_type, &detect_ctx });

    // Start sink threads
    var log_ctx: ?sink_mod.SinkContext = null;
    var log_thread: ?std.Thread = null;
    if (config.log_enabled) {
        log_ctx = .{ .consumer = ring.consumer(), .config = &config, .should_stop = &should_stop };
        log_thread = try std.Thread.spawn(.{}, logwriter.run, .{&log_ctx.?});
        std.debug.print("log sink: {s}\n", .{config.log_path});
    }

    var desktop_ctx: ?sink_mod.SinkContext = null;
    var desktop_thread: ?std.Thread = null;
    if (config.desktop_enabled) {
        desktop_ctx = .{ .consumer = ring.consumer(), .config = &config, .should_stop = &should_stop };
        desktop_thread = try std.Thread.spawn(.{}, desktop.run, .{&desktop_ctx.?});
        std.debug.print("desktop sink: enabled\n", .{});
    }

    var webhook_ctx: ?sink_mod.SinkContext = null;
    var webhook_thread: ?std.Thread = null;
    if (config.webhook_enabled and config.endpoints.len > 0) {
        webhook_ctx = .{ .consumer = ring.consumer(), .config = &config, .should_stop = &should_stop };
        webhook_thread = try std.Thread.spawn(.{}, webhook.run, .{&webhook_ctx.?});
        std.debug.print("webhook sink: {d} endpoints\n", .{config.endpoints.len});
    }

    // Session correlation table for auth_failure inference
    var sessions = session_mod.SessionTable.init(allocator, 4096);
    defer sessions.deinit();
    var timeout_ns: u64 = @as(u64, config.auth_timeout_seconds) * std.time.ns_per_s;

    // Main loop consumer — feeds session table from ring buffer events
    var session_consumer = ring.consumer();

    std.debug.print("ssh-notifier running\n", .{});
    sdNotify("READY=1\n");

    // Main loop
    while (!should_stop.load(.acquire)) {
        // Config live-reload on SIGHUP — only reload scalar values,
        // string pointers in sinks are NOT updated (they still point to old config)
        if (should_reload.load(.acquire)) {
            should_reload.store(false, .release);
            if (loadConfig(allocator)) |new_cfg| {
                // Only update scalar config values that don't involve string pointers
                // held by other threads. Full reload would require thread synchronization.
                config.auth_timeout_seconds = new_cfg.auth_timeout_seconds;
                config.notify_on_connection = new_cfg.notify_on_connection;
                config.notify_on_auth_success = new_cfg.notify_on_auth_success;
                config.notify_on_auth_failure = new_cfg.notify_on_auth_failure;
                config.notify_on_disconnect = new_cfg.notify_on_disconnect;
                timeout_ns = @as(u64, new_cfg.auth_timeout_seconds) * std.time.ns_per_s;
                // Free the new config's owned buffers (we didn't take its strings)
                var tmp = new_cfg;
                tmp.deinit();
                std.debug.print("config reloaded (scalar values)\n", .{});
            } else |err| {
                std.debug.print("config reload failed: {}, keeping current\n", .{err});
            }
        }

        // Session timeout inference — only for logfile/journal/utmp backends.
        // eBPF detects auth_success directly via exec tracepoint and can't
        // correlate connection PIDs to auth PIDs, so timeout inference would
        // produce false auth_failure events.
        if (backend_type != .ebpf) {
            while (session_consumer.pop()) |ev| {
                sessions.update(&ev);
            }
            const now: u64 = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
            var timeout_events: [32]SSHEvent = undefined;
            const n = sessions.checkTimeouts(now, timeout_ns, &timeout_events);
            for (timeout_events[0..n]) |ev| ring.push(ev);
        }

        // SIGUSR1 status dump
        if (should_dump.load(.acquire)) {
            should_dump.store(false, .release);
            std.debug.print("=== ssh-notifier status ===\n", .{});
            std.debug.print("backend: {s}\n", .{@tagName(backend_type)});
            std.debug.print("ring buffer write pos: {d}\n", .{ring.write_pos.load(.monotonic)});
            std.debug.print("active sessions: {d}\n", .{sessions.entries.count()});
            std.debug.print("===========================\n", .{});
        }

        std.Thread.sleep(500 * std.time.ns_per_ms);
    }

    // Graceful shutdown
    sdNotify("STOPPING=1\n");
    std.debug.print("shutting down\n", .{});
    detect_thread.join();
    if (webhook_thread) |t| t.join();
    if (desktop_thread) |t| t.join();
    if (log_thread) |t| t.join();
    std.debug.print("ssh-notifier stopped\n", .{});
}

fn runBackend(backend_type: backend_mod.BackendType, ctx: *backend_mod.Context) void {
    switch (backend_type) {
        .logfile => logfile.run(ctx),
        .journal => journal.run(ctx),
        .ebpf => ebpf.run(ctx),
        .utmp => utmp_mod.run(ctx),
    }
}

/// Send sd_notify state to systemd via raw Unix datagram socket.
/// No libsystemd dependency — just a socket write to $NOTIFY_SOCKET.
fn sdNotify(state: []const u8) void {
    const addr_str = std.posix.getenv("NOTIFY_SOCKET") orelse return;
    if (addr_str.len == 0) return;

    const sock = posix.socket(linux.AF.UNIX, linux.SOCK.DGRAM | linux.SOCK.CLOEXEC, 0) catch return;
    defer posix.close(sock);

    var sa: linux.sockaddr.un = .{ .path = undefined };
    @memset(&sa.path, 0);
    if (addr_str[0] == '@') {
        // Abstract socket: first byte is NUL
        sa.path[0] = 0;
        const copy_len = @min(addr_str.len - 1, sa.path.len - 1);
        @memcpy(sa.path[1 .. 1 + copy_len], addr_str[1 .. 1 + copy_len]);
    } else {
        const copy_len = @min(addr_str.len, sa.path.len);
        @memcpy(sa.path[0..copy_len], addr_str[0..copy_len]);
    }

    _ = posix.sendto(sock, state, 0, @ptrCast(&sa), @sizeOf(@TypeOf(sa))) catch {};
}

fn loadConfig(allocator: std.mem.Allocator) !Config {
    var sys_config: ?Config = null;
    var sys_content: ?[]const u8 = null;
    if (config_mod.loadFile(allocator, SYSTEM_CONFIG)) |content| {
        sys_config = try config_mod.parse(allocator, content);
        sys_content = content;
    } else |_| {}

    const home = std.posix.getenv("HOME") orelse {
        if (sys_config) |*sc| sc.ownContent(sys_content.?);
        return sys_config orelse Config{};
    };
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const user_path = std.fmt.bufPrint(&path_buf, "{s}/.config/ssh-notifier/config.toml", .{home}) catch {
        if (sys_config) |*sc| sc.ownContent(sys_content.?);
        return sys_config orelse Config{};
    };

    if (config_mod.loadFile(allocator, user_path)) |user_content| {
        const user_config = try config_mod.parse(allocator, user_content);
        if (sys_config) |sys| {
            var merged = config_mod.mergeConfigs(sys, user_config);
            merged.allocator = allocator;
            merged.ownContent(sys_content.?);
            merged.ownContent(user_content);
            if (user_config.endpoints.len > 0 and sys.endpoints.len > 0) {
                allocator.free(sys.endpoints);
            }
            return merged;
        }
        var uc = user_config;
        uc.ownContent(user_content);
        return uc;
    } else |_| {}

    if (sys_config) |*sc| {
        sc.ownContent(sys_content.?);
    }
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
    _ = @import("detect/journal.zig");
    _ = @import("detect/ebpf.zig");
    _ = @import("detect/utmp.zig");
    _ = @import("session.zig");
    _ = @import("notify/sink.zig");
    _ = @import("notify/logwriter.zig");
    _ = @import("dbus.zig");
    _ = @import("notify/desktop.zig");
    _ = @import("notify/webhook.zig");
}
