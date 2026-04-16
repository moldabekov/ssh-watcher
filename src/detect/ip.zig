const std = @import("std");

pub fn parseIPInto(ip_str: []const u8, out: *[16]u8) void {
    out.* = [_]u8{0} ** 16;
    out[10] = 0xff;
    out[11] = 0xff;
    var octets: [4]u8 = .{ 0, 0, 0, 0 };
    var idx: usize = 0;
    var cur: u16 = 0;
    for (ip_str) |ch| {
        if (ch == '.') {
            if (idx < 4) {
                octets[idx] = if (cur > 255) 255 else @intCast(cur);
                idx += 1;
                cur = 0;
            }
        } else if (ch >= '0' and ch <= '9') {
            cur = cur * 10 + (ch - '0');
        }
    }
    if (idx < 4) octets[idx] = if (cur > 255) 255 else @intCast(cur);
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
