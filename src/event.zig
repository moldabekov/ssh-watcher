const std = @import("std");

pub const EventType = enum(u8) {
    connection = 0,
    auth_success = 1,
    auth_failure = 2,
    disconnect = 3,

    pub fn toString(self: EventType) []const u8 {
        return switch (self) {
            .connection => "connection",
            .auth_success => "auth_success",
            .auth_failure => "auth_failure",
            .disconnect => "disconnect",
        };
    }

    pub fn toDisplayName(self: EventType) []const u8 {
        return switch (self) {
            .connection => "Connection",
            .auth_success => "Authentication Successful",
            .auth_failure => "Authentication Failed",
            .disconnect => "Connection Disconnected",
        };
    }
};

// NOTE: three Backend enums exist and must stay tag-name-aligned:
//   - event.Backend       (here)          — wire-stable, JSON/webhook output
//   - config.Backend                      — TOML user-facing names + 'auto'
//   - detect.backend.BackendType          — internal dispatch key
// The integer tags here are LOAD-BEARING for downstream log consumers.
// Never renumber existing values; append new ones at the end.
pub const Backend = enum(u8) {
    ebpf = 0,
    journal = 1,
    logfile = 2,
    utmp = 3,
    audit_bsm = 4,
    logstream = 5,
    utmpx_bsd = 6,

    pub fn toString(self: Backend) []const u8 {
        return switch (self) {
            .ebpf => "ebpf",
            .journal => "journal",
            .logfile => "logfile",
            .utmp => "utmp",
            .audit_bsm => "audit_bsm",
            .logstream => "logstream",
            .utmpx_bsd => "utmpx_bsd",
        };
    }
};

pub const SSHEvent = struct {
    timestamp: u64 = 0,
    event_type: EventType = .connection,
    source_ip: [16]u8 = [_]u8{0} ** 16,
    source_port: u16 = 0,
    username: [64]u8 = [_]u8{0} ** 64,
    pid: u32 = 0,
    session_id: u64 = 0,
    backend: Backend = .journal,

    pub fn setIPv4(self: *SSHEvent, a: u8, b: u8, c_byte: u8, d: u8) void {
        self.source_ip = [_]u8{0} ** 16;
        self.source_ip[10] = 0xff;
        self.source_ip[11] = 0xff;
        self.source_ip[12] = a;
        self.source_ip[13] = b;
        self.source_ip[14] = c_byte;
        self.source_ip[15] = d;
    }

    pub fn ipv4Slice(self: *const SSHEvent) [4]u8 {
        return .{ self.source_ip[12], self.source_ip[13], self.source_ip[14], self.source_ip[15] };
    }

    pub fn formatIP(self: *const SSHEvent, buf: []u8) ![]const u8 {
        const ip = self.ipv4Slice();
        return std.fmt.bufPrint(buf, "{}.{}.{}.{}", .{ ip[0], ip[1], ip[2], ip[3] });
    }

    pub fn setUsername(self: *SSHEvent, name: []const u8) void {
        self.username = [_]u8{0} ** 64;
        const len = @min(name.len, 63);
        @memcpy(self.username[0..len], name[0..len]);
    }

    pub fn usernameSlice(self: *const SSHEvent) []const u8 {
        const len = std.mem.indexOfScalar(u8, &self.username, 0) orelse self.username.len;
        return self.username[0..len];
    }
};

test "EventType toString" {
    try std.testing.expectEqualStrings("auth_success", EventType.auth_success.toString());
    try std.testing.expectEqualStrings("disconnect", EventType.disconnect.toString());
}

test "SSHEvent IPv4" {
    var ev = SSHEvent{};
    ev.setIPv4(192, 168, 1, 100);

    var buf: [16]u8 = undefined;
    const ip_str = try ev.formatIP(&buf);
    try std.testing.expectEqualStrings("192.168.1.100", ip_str);
}

test "SSHEvent username" {
    var ev = SSHEvent{};
    ev.setUsername("root");
    try std.testing.expectEqualStrings("root", ev.usernameSlice());
}

test "SSHEvent username truncation" {
    var ev = SSHEvent{};
    const long_name = "a" ** 100;
    ev.setUsername(long_name);
    try std.testing.expectEqual(@as(usize, 63), ev.usernameSlice().len);
}
