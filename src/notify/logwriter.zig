const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const sink = @import("sink.zig");

pub fn run(ctx: *sink.SinkContext) void {
    runImpl(ctx) catch |err| {
        std.log.err("logwriter: {}", .{err});
    };
}

fn runImpl(ctx: *sink.SinkContext) !void {
    const file = try std.fs.createFileAbsolute(ctx.config.log_path, .{ .truncate = false });
    defer file.close();
    try file.seekFromEnd(0);

    while (!ctx.stopped()) {
        if (ctx.consumer.pop()) |ev| {
            if (!sink.shouldNotify(ctx.config, ev.event_type)) continue;
            writeEvent(file, &ev) catch |err| {
                std.log.err("logwriter write: {}", .{err});
                continue;
            };
        } else {
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }
    }
}

pub fn writeEvent(file: std.fs.File, ev: *const SSHEvent) !void {
    var ip_buf: [46]u8 = undefined;
    const ip_str = ev.formatIP(&ip_buf) catch "unknown";

    var escaped_user_buf: [256]u8 = undefined;
    const escaped_user = jsonEscape(ev.usernameSlice(), &escaped_user_buf);

    var buf: [1024]u8 = undefined;
    var stream = std.io.fixedBufferStream(&buf);
    try stream.writer().print(
        "{{\"timestamp\":{d},\"event_type\":\"{s}\",\"source_ip\":\"{s}\",\"source_port\":{d},\"username\":\"{s}\",\"pid\":{d},\"session_id\":{d}}}\n",
        .{ ev.timestamp, ev.event_type.toString(), ip_str, ev.source_port, escaped_user, ev.pid, ev.session_id },
    );
    try file.writeAll(stream.getWritten());
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

test "writeEvent JSON format" {
    var ev = SSHEvent{};
    ev.timestamp = 1000;
    ev.event_type = .auth_success;
    ev.setIPv4(10, 0, 0, 1);
    ev.source_port = 54321;
    ev.setUsername("root");
    ev.pid = 1234;

    // Write to a temp file
    var tmp_dir = std.testing.tmpDir(.{});
    defer tmp_dir.cleanup();
    const file = try tmp_dir.dir.createFile("test.log", .{});

    try writeEvent(file, &ev);
    file.close();

    const rfile = try tmp_dir.dir.openFile("test.log", .{});
    defer rfile.close();
    var read_buf: [1024]u8 = undefined;
    const n = try rfile.readAll(&read_buf);
    const out = read_buf[0..n];
    try std.testing.expect(std.mem.indexOf(u8, out, "\"event_type\":\"auth_success\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, out, "\"username\":\"root\"") != null);
    try std.testing.expectEqual(@as(u8, '\n'), out[out.len - 1]);
}
