const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
pub const event = @import("event.zig");
const ring_buffer = @import("ring_buffer.zig");
const BroadcastBuffer = ring_buffer.BroadcastBuffer;
const SSHEvent = event.SSHEvent;
const config_mod = @import("config.zig");
const Config = config_mod.Config;
const backend_mod = @import("detect/backend.zig");
const logfile = @import("detect/logfile.zig");
const logwriter = @import("notify/logwriter.zig");
const desktop = @import("notify/desktop.zig");
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
    const sa = posix.Sigaction{
        .handler = .{ .handler = &handleSignal },
        .mask = std.mem.zeroes(posix.sigset_t),
        .flags = linux.SA.RESTART,
    };
    posix.sigaction(posix.SIG.TERM, &sa, null);
    posix.sigaction(posix.SIG.INT, &sa, null);
    posix.sigaction(posix.SIG.HUP, &sa, null);
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

    var log_ctx: ?sink_mod.SinkContext = null;
    var log_thread: ?std.Thread = null;
    if (config.log_enabled) {
        log_ctx = .{
            .consumer = ring.consumer(),
            .config = &config,
            .should_stop = &should_stop,
        };
        log_thread = try std.Thread.spawn(.{}, logwriter.run, .{&log_ctx.?});
        std.debug.print("log sink: {s}\n", .{config.log_path});
    }

    var desktop_ctx: ?sink_mod.SinkContext = null;
    var desktop_thread: ?std.Thread = null;
    if (config.desktop_enabled) {
        desktop_ctx = .{
            .consumer = ring.consumer(),
            .config = &config,
            .should_stop = &should_stop,
        };
        desktop_thread = try std.Thread.spawn(.{}, desktop.run, .{&desktop_ctx.?});
        std.debug.print("desktop sink: enabled\n", .{});
    }

    std.debug.print("ssh-notifier running\n", .{});

    while (!should_stop.load(.acquire)) {
        if (should_reload.load(.acquire)) {
            std.debug.print("config reload (SIGHUP)\n", .{});
            should_reload.store(false, .release);
        }
        std.Thread.sleep(500 * std.time.ns_per_ms);
    }

    std.debug.print("shutting down\n", .{});
    detect_thread.join();
    if (desktop_thread) |t| t.join();
    if (log_thread) |t| t.join();
    std.debug.print("ssh-notifier stopped\n", .{});
}

fn runBackend(backend_type: backend_mod.BackendType, ctx: *backend_mod.Context) void {
    switch (backend_type) {
        .logfile => logfile.run(ctx),
        else => std.log.err("backend {s} not yet implemented", .{@tagName(backend_type)}),
    }
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
            // sys endpoints were replaced by merge if user had endpoints;
            // free sys endpoints if they were superseded
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
    _ = @import("notify/sink.zig");
    _ = @import("notify/logwriter.zig");
    _ = @import("dbus.zig");
    _ = @import("notify/desktop.zig");
}
