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
            std.Thread.sleep(50 * std.time.ns_per_ms);
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
        notifySendFallback(title, body, urgency);
        return;
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
