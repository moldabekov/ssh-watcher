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

    var esc_title_buf: [512]u8 = undefined;
    var esc_body_buf: [1024]u8 = undefined;
    const esc_title = escapeAppleScript(title, &esc_title_buf);
    const esc_body = escapeAppleScript(body, &esc_body_buf);

    var script_buf: [2048]u8 = undefined;
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

/// Escape AppleScript string-literal metacharacters. {username} and IP
/// fields come from attacker-controlled SSH data, so we must defend
/// against quote/backslash injection and strip control chars that
/// could disrupt the `osascript -e` command line.
fn escapeAppleScript(input: []const u8, buf: []u8) []const u8 {
    var i: usize = 0;
    for (input) |ch| {
        if (i >= buf.len) break;
        if (ch == '"' or ch == '\\') {
            if (i + 2 > buf.len) break;
            buf[i] = '\\';
            i += 1;
            buf[i] = ch;
            i += 1;
        } else if (ch == '\n' or ch == '\r' or ch == '\t') {
            buf[i] = ' ';
            i += 1;
        } else if (ch >= 0x20 and ch != 0x7f) {
            buf[i] = ch;
            i += 1;
        }
        // else: drop control char
    }
    return buf[0..i];
}

test "escapeAppleScript doubles quotes" {
    var buf: [64]u8 = undefined;
    const out = escapeAppleScript("hello \"world\"", &buf);
    try std.testing.expectEqualStrings("hello \\\"world\\\"", out);
}

test "escapeAppleScript doubles backslashes" {
    var buf: [64]u8 = undefined;
    const out = escapeAppleScript("a\\b", &buf);
    try std.testing.expectEqualStrings("a\\\\b", out);
}

test "escapeAppleScript replaces newlines with spaces" {
    var buf: [64]u8 = undefined;
    const out = escapeAppleScript("line1\nline2\r\nline3\tend", &buf);
    try std.testing.expectEqualStrings("line1 line2  line3 end", out);
}

test "escapeAppleScript drops control chars" {
    var buf: [64]u8 = undefined;
    const out = escapeAppleScript("a\x00b\x07c\x1fd\x7fe", &buf);
    try std.testing.expectEqualStrings("abcde", out);
}

test "escapeAppleScript respects buf overflow" {
    var buf: [4]u8 = undefined;
    // Two quotes would need 4 bytes escaped; the second shouldn't overflow.
    const out = escapeAppleScript("\"\"\"", &buf);
    try std.testing.expectEqualStrings("\\\"\\\"", out);
}
