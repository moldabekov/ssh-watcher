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
