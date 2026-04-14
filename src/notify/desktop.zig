const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const EventType = @import("../event.zig").EventType;
const Config = @import("../config.zig").Config;
const Urgency = @import("../config.zig").Urgency;
const dbus = @import("../dbus.zig");
const template = @import("../template.zig");
const sink = @import("sink.zig");

pub fn run(ctx: *sink.SinkContext) void {
    // Probe once at startup — if no notification path works, disable silently
    if (!probeNotifications()) {
        std.log.warn("desktop: no notification daemon found, disabling desktop sink", .{});
        return;
    }

    while (!ctx.stopped()) {
        if (ctx.consumer.pop()) |ev| {
            if (!sink.shouldNotify(ctx.config, ev.event_type)) continue;
            sendNotification(ctx.config, &ev);
        } else {
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }
    }
}

/// Check if any user has a D-Bus session bus socket.
/// We don't try authenticating (dbus-broker may reject cross-UID auth),
/// just verify the socket file exists — notify-send fallback with UID
/// switch can still deliver even if our D-Bus direct path fails.
fn probeNotifications() bool {
    var dir = std.fs.openDirAbsolute("/run/user", .{ .iterate = true }) catch return false;
    defer dir.close();
    var iter = dir.iterate();
    while (iter.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        _ = std.fmt.parseInt(std.posix.uid_t, entry.name, 10) catch continue;
        var path_buf: [256]u8 = undefined;
        const bus_path = std.fmt.bufPrint(&path_buf, "/run/user/{s}/bus", .{entry.name}) catch continue;
        std.fs.accessAbsolute(bus_path, .{}) catch continue;
        return true;
    }
    return false;
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
    var dir = std.fs.openDirAbsolute("/run/user", .{ .iterate = true }) catch return;
    defer dir.close();
    var iter = dir.iterate();

    // Remember first user for notify-send fallback
    var first_uid: ?std.posix.uid_t = null;
    var first_name_buf: [32]u8 = undefined;
    var first_name_len: usize = 0;

    // Try D-Bus direct for each user — stop after first success
    while (iter.next() catch null) |entry| {
        if (entry.kind != .directory) continue;
        const uid = std.fmt.parseInt(std.posix.uid_t, entry.name, 10) catch continue;
        if (first_uid == null) {
            first_uid = uid;
            first_name_len = @min(entry.name.len, first_name_buf.len);
            @memcpy(first_name_buf[0..first_name_len], entry.name[0..first_name_len]);
        }
        var addr_buf: [256]u8 = undefined;
        const addr = std.fmt.bufPrint(&addr_buf, "unix:path=/run/user/{s}/bus", .{entry.name}) catch continue;
        if (sendViaDbus(addr, title, body, urgency)) return;
    }

    // D-Bus failed for all users — try notify-send with user env vars
    if (first_uid) |uid| {
        notifySendFallback(title, body, urgency, uid, first_name_buf[0..first_name_len]);
    }
}

fn sendViaDbus(addr: []const u8, title: []const u8, body: []const u8, urgency: u8) bool {
    var conn = dbus.Connection.connect(addr) catch return false;
    defer conn.close();
    conn.notify(title, body, urgency) catch return false;
    return true;
}

fn notifySendFallback(title: []const u8, body: []const u8, urgency: u8, target_uid: std.posix.uid_t, uid_name: []const u8) void {
    const u_str: []const u8 = if (urgency == 0) "low" else if (urgency == 2) "critical" else "normal";

    // Use `env` to inject DBUS_SESSION_BUS_ADDRESS and XDG_RUNTIME_DIR
    // so notify-send can find the target user's session bus
    var bus_env: [256]u8 = undefined;
    const bus_arg = std.fmt.bufPrint(&bus_env, "DBUS_SESSION_BUS_ADDRESS=unix:path=/run/user/{s}/bus", .{uid_name}) catch return;
    var xdg_env: [128]u8 = undefined;
    const xdg_arg = std.fmt.bufPrint(&xdg_env, "XDG_RUNTIME_DIR=/run/user/{s}", .{uid_name}) catch return;

    var child = std.process.Child.init(
        &.{ "env", bus_arg, xdg_arg, "notify-send", "-u", u_str, title, body },
        std.heap.page_allocator,
    );
    child.stderr_behavior = .Ignore;
    child.uid = target_uid;
    child.gid = target_uid;

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
    return switch (u) {
        .low => 0,
        .normal => 1,
        .critical => 2,
    };
}

test "urgencyByte" {
    const config = Config{};
    try std.testing.expectEqual(@as(u8, 1), urgencyByte(&config, .auth_success));
    try std.testing.expectEqual(@as(u8, 2), urgencyByte(&config, .auth_failure));
    try std.testing.expectEqual(@as(u8, 0), urgencyByte(&config, .connection));
    try std.testing.expectEqual(@as(u8, 0), urgencyByte(&config, .disconnect));
}
