const std = @import("std");
const posix = std.posix;
const net = std.net;
const linux = std.os.linux;

pub const Connection = struct {
    stream: net.Stream,
    serial: u32 = 1,

    pub fn connect(bus_address: []const u8) !Connection {
        const path = extractSocketPath(bus_address) orelse return error.InvalidArgument;
        const stream = try net.connectUnixSocket(path);
        var conn = Connection{ .stream = stream };
        try conn.authenticate();
        try conn.hello();
        return conn;
    }

    pub fn close(self: *Connection) void {
        self.stream.close();
    }

    fn authenticate(self: *Connection) !void {
        _ = try self.stream.write(&[_]u8{0});
        const uid = linux.getuid();
        var uid_buf: [32]u8 = undefined;
        const uid_str = try std.fmt.bufPrint(&uid_buf, "{d}", .{uid});
        var hex_buf: [64]u8 = undefined;
        var hex_len: usize = 0;
        for (uid_str) |byte| {
            const hex = std.fmt.bytesToHex([_]u8{byte}, .lower);
            hex_buf[hex_len] = hex[0];
            hex_buf[hex_len + 1] = hex[1];
            hex_len += 2;
        }
        var auth_buf: [128]u8 = undefined;
        const auth_msg = try std.fmt.bufPrint(&auth_buf, "AUTH EXTERNAL {s}\r\n", .{hex_buf[0..hex_len]});
        _ = try self.stream.write(auth_msg);
        var resp: [256]u8 = undefined;
        const n = try self.stream.read(&resp);
        if (n < 2 or !std.mem.startsWith(u8, resp[0..n], "OK")) return error.AuthenticationFailed;
        _ = try self.stream.write("BEGIN\r\n");
    }

    fn hello(self: *Connection) !void {
        try self.methodCall("org.freedesktop.DBus", "/org/freedesktop/DBus", "org.freedesktop.DBus", "Hello", "", &.{});
        var discard: [1024]u8 = undefined;
        _ = self.stream.read(&discard) catch {};
    }

    pub fn notify(self: *Connection, summary: []const u8, body: []const u8, urgency: u8) !void {
        var buf: [4096]u8 = undefined;
        var p: usize = 0;
        p += writeStr(&buf, p, "ssh-notifier");
        p += writeU32(&buf, p, 0);
        p += writeStr(&buf, p, "dialog-warning");
        p += writeStr(&buf, p, summary);
        p += writeStr(&buf, p, body);
        p += writeU32(&buf, p, 0); // empty actions array
        p += writeHints(&buf, p, urgency);
        p += writeI32(&buf, p, -1);

        try self.methodCall(
            "org.freedesktop.Notifications",
            "/org/freedesktop/Notifications",
            "org.freedesktop.Notifications",
            "Notify",
            "susssasa{sv}i",
            buf[0..p],
        );
        var discard: [512]u8 = undefined;
        _ = self.stream.read(&discard) catch {};
    }

    fn methodCall(self: *Connection, dest: []const u8, path: []const u8, iface: []const u8, member: []const u8, sig: []const u8, body_bytes: []const u8) !void {
        var fields: [512]u8 = undefined;
        var fp: usize = 0;
        fp += writeField(&fields, fp, 1, 'o', path);
        fp += writeField(&fields, fp, 2, 's', iface);
        fp += writeField(&fields, fp, 3, 's', member);
        fp += writeField(&fields, fp, 6, 's', dest);
        if (sig.len > 0) fp += writeFieldSig(&fields, fp, sig);

        var hdr: [16]u8 = undefined;
        hdr[0] = 'l';
        hdr[1] = 1;
        hdr[2] = 0;
        hdr[3] = 1;
        @memcpy(hdr[4..8], std.mem.asBytes(&@as(u32, @intCast(body_bytes.len))));
        const serial = self.serial;
        self.serial += 1;
        @memcpy(hdr[8..12], std.mem.asBytes(&serial));
        @memcpy(hdr[12..16], std.mem.asBytes(&@as(u32, @intCast(fp))));

        // Fixed header is 16 bytes, then fp bytes of field data. Body starts at 8-byte alignment.
        const pad_len = align8(16 + fp) - (16 + fp);
        const zeros = [_]u8{0} ** 8;

        _ = try self.stream.write(&hdr);
        _ = try self.stream.write(fields[0..fp]);
        if (pad_len > 0) _ = try self.stream.write(zeros[0..pad_len]);
        if (body_bytes.len > 0) _ = try self.stream.write(body_bytes);
    }
};

fn writeField(buf: []u8, pos: usize, code: u8, sig_char: u8, value: []const u8) usize {
    var p = align8(pos);
    @memset(buf[pos..p], 0); // struct alignment padding
    buf[p] = code;
    p += 1;
    buf[p] = 1; // variant signature length
    p += 1;
    buf[p] = sig_char;
    p += 1;
    buf[p] = 0; // signature null terminator
    p += 1;
    // p is now at struct_start + 4, which is always 4-aligned (struct starts at 8-aligned)
    // so no additional padding needed before the string value
    p += writeStr(buf, p, value);
    return p - pos;
}

fn writeFieldSig(buf: []u8, pos: usize, sig: []const u8) usize {
    var p = align8(pos);
    @memset(buf[pos..p], 0);
    buf[p] = 8;
    p += 1;
    buf[p] = 1;
    p += 1;
    buf[p] = 'g';
    p += 1;
    buf[p] = 0;
    p += 1;
    buf[p] = @intCast(sig.len);
    p += 1;
    @memcpy(buf[p .. p + sig.len], sig);
    p += sig.len;
    buf[p] = 0;
    p += 1;
    return p - pos;
}

fn writeStr(buf: []u8, pos: usize, s: []const u8) usize {
    @memcpy(buf[pos .. pos + 4], std.mem.asBytes(&@as(u32, @intCast(s.len))));
    @memcpy(buf[pos + 4 .. pos + 4 + s.len], s);
    buf[pos + 4 + s.len] = 0;
    const total = align4(4 + s.len + 1);
    @memset(buf[pos + 4 + s.len + 1 .. pos + total], 0);
    return total;
}

fn writeU32(buf: []u8, pos: usize, val: u32) usize {
    @memcpy(buf[pos .. pos + 4], std.mem.asBytes(&val));
    return 4;
}

fn writeI32(buf: []u8, pos: usize, val: i32) usize {
    @memcpy(buf[pos .. pos + 4], std.mem.asBytes(&val));
    return 4;
}

fn writeHints(buf: []u8, pos: usize, urgency: u8) usize {
    var p = pos;
    // Array length field (4 bytes, filled at the end)
    p += 4;
    // Pad to 8-byte alignment for dict entry (D-Bus spec: {sv} entries are 8-aligned)
    const content_start = align8(p);
    @memset(buf[p..content_start], 0);
    p = content_start;
    // Dict entry: string key "urgency"
    p += writeStr(buf, p, "urgency");
    // Dict entry: variant value — signature "y" (byte) + value
    buf[p] = 1; // signature length
    p += 1;
    buf[p] = 'y'; // byte type
    p += 1;
    buf[p] = 0; // signature null
    p += 1;
    buf[p] = urgency;
    p += 1;
    // Array length = content bytes only (excluding alignment padding after length field)
    const array_len: u32 = @intCast(p - content_start);
    @memcpy(buf[pos .. pos + 4], std.mem.asBytes(&array_len));
    return p - pos;
}

fn align4(v: usize) usize {
    return (v + 3) & ~@as(usize, 3);
}
fn align8(v: usize) usize {
    return (v + 7) & ~@as(usize, 7);
}

pub fn extractSocketPath(address: []const u8) ?[]const u8 {
    const prefix = "unix:path=";
    if (!std.mem.startsWith(u8, address, prefix)) return null;
    const rest = address[prefix.len..];
    if (std.mem.indexOfScalar(u8, rest, ',')) |comma| return rest[0..comma];
    return rest;
}

test "extractSocketPath" {
    try std.testing.expectEqualStrings("/run/user/1000/bus", extractSocketPath("unix:path=/run/user/1000/bus").?);
    try std.testing.expectEqualStrings("/run/user/1000/bus", extractSocketPath("unix:path=/run/user/1000/bus,guid=abc").?);
    try std.testing.expectEqual(@as(?[]const u8, null), extractSocketPath("tcp:host=localhost"));
}

test "align" {
    try std.testing.expectEqual(@as(usize, 8), align8(5));
    try std.testing.expectEqual(@as(usize, 8), align4(7));
    try std.testing.expectEqual(@as(usize, 8), align8(8));
    try std.testing.expectEqual(@as(usize, 4), align4(4));
}
