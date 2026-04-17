// sshd log line parser. Shared by the Linux logfile/journal backends and
// the macOS logstream backend. Assumes stock OpenSSH message formats:
//   "Accepted password for <user> from <ip> port <port> ssh2"
//   "Failed password for [invalid user ]<user> from <ip> port <port> ssh2"
//   "Disconnected from user <user> <ip> port <port>"
//   "Connection closed|reset by [authenticating user <user> ]<ip> port <port>"
// macOS ships an Apple-patched OpenSSH; message text has historically
// matched stock sshd. If Apple diverges (or OpenSSH bumps major versions),
// the parser may silently stop producing events — Context.parse_misses
// in backend.zig is surfaced via SIGUSR1 to detect this.
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
    // Handles both:
    //   "Connection closed by <IP> port <PORT>"
    //   "Connection closed by authenticating user <USER> <IP> port <PORT> [preauth]"
    //   "Connection reset by <IP> port <PORT>"
    const by_pos = indexOf(line, " by ") orelse return null;
    var rest = line[by_pos + 4 ..];
    var username: []const u8 = "";

    // Handle "authenticating user <USER> " prefix
    if (std.mem.startsWith(u8, rest, "authenticating user ")) {
        rest = rest["authenticating user ".len..];
        // "USER IP port PORT" — find " port " and extract user+IP from before it
        const port_pos = indexOf(rest, " port ") orelse return null;
        const user_ip = rest[0..port_pos];
        const last_space = std.mem.lastIndexOfScalar(u8, user_ip, ' ') orelse return null;
        username = user_ip[0..last_space];
        const after_port = rest[port_pos + 6 ..];
        const port_end = indexOf(after_port, " ") orelse after_port.len;
        return .{
            .event_type = .auth_failure,
            .username = username,
            .ip = user_ip[last_space + 1 ..],
            .port = after_port[0..port_end],
            .pid = extractPid(line),
        };
    }

    const port_pos = indexOf(rest, " port ") orelse return null;
    const after_port = rest[port_pos + 6 ..];
    const port_end = indexOf(after_port, " ") orelse after_port.len;
    return .{
        .event_type = .disconnect,
        .username = username,
        .ip = rest[0..port_pos],
        .port = after_port[0..port_end],
        .pid = extractPid(line),
    };
}

fn extractPid(line: []const u8) ?u32 {
    // Match both "sshd[PID]" and "sshd-session[PID]"
    const bracket_open = indexOf(line, "sshd-session[") orelse
        (indexOf(line, "sshd[") orelse return null);
    const pid_start = (indexOfFrom(line, bracket_open, "[") orelse return null) + 1;
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

test "parse connection closed by authenticating user" {
    const r = parseLine("sshd-session[862330]: Connection closed by authenticating user moldabekov ::1 port 46820 [preauth]").?;
    try std.testing.expectEqual(EventType.auth_failure, r.event_type);
    try std.testing.expectEqualStrings("moldabekov", r.username);
    try std.testing.expectEqualStrings("::1", r.ip);
    try std.testing.expectEqualStrings("46820", r.port.?);
    try std.testing.expectEqual(@as(?u32, 862330), r.pid);
}

test "parse sshd-session pid" {
    const r = parseLine("sshd-session[12345]: Accepted password for root from 10.0.0.1 port 22 ssh2").?;
    try std.testing.expectEqual(@as(?u32, 12345), r.pid);
}

test "unrecognized returns null" {
    try std.testing.expectEqual(@as(?ParseResult, null), parseLine("Starting session: shell on pts/0"));
}
