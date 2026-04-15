const std = @import("std");
const SSHEvent = @import("event.zig").SSHEvent;

pub fn expand(template_str: []const u8, ev: *const SSHEvent, buf: []u8) ![]const u8 {
    var stream = std.io.fixedBufferStream(buf);
    const writer = stream.writer();
    var i: usize = 0;

    while (i < template_str.len) {
        if (template_str[i] == '{') {
            if (findVarEnd(template_str, i + 1)) |end| {
                const var_name = template_str[i + 1 .. end];
                const pos_before = stream.pos;
                try writeVar(writer, var_name, ev);
                i = end + 1;
                // If variable expanded to empty, skip a trailing '@'
                // so "{username}@{source_ip}" renders as just "{source_ip}"
                if (stream.pos == pos_before and i < template_str.len and template_str[i] == '@') {
                    i += 1;
                }
            } else {
                try writer.writeByte('{');
                i += 1;
            }
        } else {
            try writer.writeByte(template_str[i]);
            i += 1;
        }
    }
    return stream.getWritten();
}

/// Find closing `}` for a variable name. Returns null if the content between
/// `{` and `}` is not a valid identifier (contains non-alphanumeric/underscore chars).
/// This allows literal `{` in JSON templates to pass through.
fn findVarEnd(s: []const u8, start: usize) ?usize {
    var j = start;
    while (j < s.len) : (j += 1) {
        if (s[j] == '}') return j;
        if (!std.ascii.isAlphanumeric(s[j]) and s[j] != '_') return null;
    }
    return null;
}

fn writeVar(writer: anytype, name: []const u8, ev: *const SSHEvent) !void {
    if (std.mem.eql(u8, name, "event_type")) {
        try writer.writeAll(ev.event_type.toDisplayName());
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

/// Like expand but JSON-escapes all string variable values.
/// Use for webhook payload templates where output must be valid JSON.
pub fn expandJsonSafe(template_str: []const u8, ev: *const SSHEvent, buf: []u8) ![]const u8 {
    var stream = std.io.fixedBufferStream(buf);
    const writer = stream.writer();
    var i: usize = 0;

    while (i < template_str.len) {
        if (template_str[i] == '{') {
            if (findVarEnd(template_str, i + 1)) |end| {
                const var_name = template_str[i + 1 .. end];
                try writeVarJsonSafe(writer, var_name, ev);
                i = end + 1;
            } else {
                try writer.writeByte('{');
                i += 1;
            }
        } else {
            try writer.writeByte(template_str[i]);
            i += 1;
        }
    }
    return stream.getWritten();
}

fn writeVarJsonSafe(writer: anytype, name: []const u8, ev: *const SSHEvent) !void {
    if (std.mem.eql(u8, name, "username")) {
        try writeJsonEscaped(writer, ev.usernameSlice());
    } else if (std.mem.eql(u8, name, "source_ip")) {
        var ip_buf: [46]u8 = undefined;
        const ip_str = try ev.formatIP(&ip_buf);
        try writeJsonEscaped(writer, ip_str);
    } else {
        // Non-string fields (event_type, port, pid, etc.) are safe as-is
        try writeVar(writer, name, ev);
    }
}

fn writeJsonEscaped(writer: anytype, s: []const u8) !void {
    for (s) |c| {
        switch (c) {
            '"' => try writer.writeAll("\\\""),
            '\\' => try writer.writeAll("\\\\"),
            '\n' => try writer.writeAll("\\n"),
            '\r' => try writer.writeAll("\\r"),
            '\t' => try writer.writeAll("\\t"),
            else => try writer.writeByte(c),
        }
    }
}

test "expandJsonSafe escapes username" {
    var ev = SSHEvent{};
    ev.setUsername("user\"with\\quotes");
    ev.event_type = .auth_failure;
    var buf: [256]u8 = undefined;
    const result = try expandJsonSafe("{\"user\": \"{username}\"}", &ev, &buf);
    try std.testing.expect(std.mem.indexOf(u8, result, "user\\\"with\\\\quotes") != null);
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
    const result = try expand("SSH: {event_type}", &ev, &buf);
    try std.testing.expectEqualStrings("SSH: Authentication Failed", result);
}

test "expand literal text" {
    var ev = SSHEvent{};
    var buf: [256]u8 = undefined;
    const result = try expand("Hello world", &ev, &buf);
    try std.testing.expectEqualStrings("Hello world", result);
}

test "expand empty username skips @" {
    var ev = SSHEvent{};
    ev.setIPv4(10, 0, 0, 1);
    // username is empty (default)
    var buf: [256]u8 = undefined;
    const result = try expand("{username}@{source_ip}", &ev, &buf);
    try std.testing.expectEqualStrings("10.0.0.1", result);
}

test "expand unknown var passed through" {
    var ev = SSHEvent{};
    var buf: [256]u8 = undefined;
    const result = try expand("{unknown}", &ev, &buf);
    try std.testing.expectEqualStrings("{unknown}", result);
}
