const std = @import("std");

pub fn parseIPInto(ip_str: []const u8, out: *[16]u8) void {
    out.* = [_]u8{0} ** 16;
    out[10] = 0xff;
    out[11] = 0xff;
    var octets: [4]u8 = .{ 0, 0, 0, 0 };
    var idx: usize = 0;
    // Accumulate in u32 and clamp to 255 each step: input is attacker-
    // controlled (sshd log line / utmpx ut_host), so a long numeric run
    // would otherwise overflow a u16 accumulator.
    var cur: u32 = 0;
    for (ip_str) |ch| {
        if (ch == '.') {
            if (idx < 4) {
                octets[idx] = @intCast(cur);
                idx += 1;
                cur = 0;
            }
        } else if (ch >= '0' and ch <= '9') {
            const next = cur * 10 + (ch - '0');
            cur = if (next > 255) 255 else next;
        }
    }
    if (idx < 4) octets[idx] = @intCast(cur);
    out[12] = octets[0];
    out[13] = octets[1];
    out[14] = octets[2];
    out[15] = octets[3];
}

test "parseIPInto" {
    var ip: [16]u8 = undefined;
    parseIPInto("192.168.1.100", &ip);
    try std.testing.expectEqual(@as(u8, 192), ip[12]);
    try std.testing.expectEqual(@as(u8, 168), ip[13]);
    try std.testing.expectEqual(@as(u8, 1), ip[14]);
    try std.testing.expectEqual(@as(u8, 100), ip[15]);
}

test "parseIPInto clamps long numeric runs without overflow" {
    var ip: [16]u8 = undefined;
    // 5+ digit run used to overflow u16 accumulator (panic in Debug,
    // silent wrap in ReleaseSmall). Now clamps to 255 per octet.
    parseIPInto("66666", &ip);
    try std.testing.expectEqual(@as(u8, 255), ip[12]);
    try std.testing.expectEqual(@as(u8, 0), ip[13]);
    parseIPInto("999999999.0.0.0", &ip);
    try std.testing.expectEqual(@as(u8, 255), ip[12]);
    try std.testing.expectEqual(@as(u8, 0), ip[13]);
}

test "parseIPInto non-numeric hostname yields zero" {
    var ip: [16]u8 = undefined;
    parseIPInto("example.com", &ip);
    try std.testing.expectEqual(@as(u8, 0), ip[12]);
    try std.testing.expectEqual(@as(u8, 0), ip[13]);
    try std.testing.expectEqual(@as(u8, 0), ip[14]);
    try std.testing.expectEqual(@as(u8, 0), ip[15]);
}
