const std = @import("std");
const http = std.http;
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
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }
    }
}

fn sendWithRetry(ep: WebhookEndpoint, ev: *const SSHEvent) void {
    var delay_ms: u64 = 1000;
    for (0..ep.max_retries + 1) |attempt| {
        if (attempt > 0) std.Thread.sleep(delay_ms * std.time.ns_per_ms);
        delay_ms *= 2;
        if (sendOnce(ep, ev)) return;
    }
    std.log.err("webhook: retries exhausted for {s}", .{ep.url});
}

fn sendOnce(ep: WebhookEndpoint, ev: *const SSHEvent) bool {
    var payload_buf: [4096]u8 = undefined;
    const payload = buildPayload(ep, ev, &payload_buf) catch return false;

    var client: http.Client = .{ .allocator = std.heap.page_allocator };
    defer client.deinit();

    const result = client.fetch(.{
        .location = .{ .url = ep.url },
        .method = .POST,
        .payload = payload,
        .extra_headers = &.{
            .{ .name = "Content-Type", .value = "application/json" },
        },
    }) catch return false;

    return result.status == .ok or result.status == .no_content or result.status == .accepted;
}

fn buildPayload(ep: WebhookEndpoint, ev: *const SSHEvent, buf: []u8) ![]const u8 {
    if (ep.payload_template) |tmpl| return template.expand(tmpl, ev, buf);
    return defaultPayload(ev, buf);
}

pub fn defaultPayload(ev: *const SSHEvent, buf: []u8) ![]const u8 {
    var ip_buf: [46]u8 = undefined;
    const ip = ev.formatIP(&ip_buf) catch "unknown";

    var escaped_user_buf: [256]u8 = undefined;
    const escaped_user = jsonEscape(ev.usernameSlice(), &escaped_user_buf);

    var stream = std.io.fixedBufferStream(buf);
    try stream.writer().print(
        "{{\"timestamp\":{d},\"event_type\":\"{s}\",\"source_ip\":\"{s}\",\"source_port\":{d},\"username\":\"{s}\",\"pid\":{d},\"session_id\":{d}}}",
        .{ ev.timestamp, ev.event_type.toString(), ip, ev.source_port, escaped_user, ev.pid, ev.session_id },
    );
    return stream.getWritten();
}

fn jsonEscape(input: []const u8, buf: []u8) []const u8 {
    var i: usize = 0;
    for (input) |c| {
        switch (c) {
            '"' => {
                if (i + 2 > buf.len) break;
                buf[i] = '\\';
                buf[i + 1] = '"';
                i += 2;
            },
            '\\' => {
                if (i + 2 > buf.len) break;
                buf[i] = '\\';
                buf[i + 1] = '\\';
                i += 2;
            },
            '\n' => {
                if (i + 2 > buf.len) break;
                buf[i] = '\\';
                buf[i + 1] = 'n';
                i += 2;
            },
            else => {
                if (i >= buf.len) break;
                buf[i] = c;
                i += 1;
            },
        }
    }
    return buf[0..i];
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

test "defaultPayload escapes special chars" {
    var ev = SSHEvent{};
    ev.event_type = .auth_failure;
    ev.setUsername("user\"with\\quotes");
    var buf: [1024]u8 = undefined;
    const p = try defaultPayload(&ev, &buf);
    try std.testing.expect(std.mem.indexOf(u8, p, "user\\\"with\\\\quotes") != null);
}

test "jsonEscape" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("hello", jsonEscape("hello", &buf));
    try std.testing.expectEqualStrings("a\\\"b", jsonEscape("a\"b", &buf));
    try std.testing.expectEqualStrings("a\\\\b", jsonEscape("a\\b", &buf));
    try std.testing.expectEqualStrings("a\\nb", jsonEscape("a\nb", &buf));
}
