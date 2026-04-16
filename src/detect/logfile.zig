const std = @import("std");
const posix = std.posix;
const linux = std.os.linux;
const SSHEvent = @import("../event.zig").SSHEvent;
const Context = @import("backend.zig").Context;
const patterns = @import("patterns.zig");
const ip = @import("ip.zig");

const log_paths = [_][]const u8{ "/var/log/auth.log", "/var/log/secure" };

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| {
        std.log.err("logfile backend: {}", .{err});
    };
}

fn runImpl(ctx: *Context) !void {
    var log_path: []const u8 = undefined;
    for (log_paths) |p| {
        std.fs.accessAbsolute(p, .{}) catch continue;
        log_path = p;
        break;
    } else return error.FileNotFound;

    const file = try std.fs.openFileAbsolute(log_path, .{});
    defer file.close();
    const stat = try file.stat();
    try file.seekTo(stat.size);

    // inotify setup — use raw u32 flags for 0.15.2 API
    const ifd = try posix.inotify_init1(linux.IN.CLOEXEC | linux.IN.NONBLOCK);
    defer posix.close(ifd);
    _ = try posix.inotify_add_watch(ifd, log_path, linux.IN.MODIFY);

    var line_buf: [4096]u8 = undefined;
    var line_len: usize = 0;
    var read_buf: [4096]u8 = undefined;
    var pollfds = [_]posix.pollfd{.{ .fd = ifd, .events = linux.POLL.IN, .revents = 0 }};

    while (!ctx.stopped()) {
        const ready = posix.poll(&pollfds, 1000) catch 0;
        if (ready == 0) continue;

        // Drain inotify events
        _ = posix.read(ifd, &read_buf) catch 0;

        // Read new data from log file
        while (true) {
            const n = file.read(&read_buf) catch break;
            if (n == 0) break;
            for (read_buf[0..n]) |byte| {
                if (byte == '\n') {
                    if (line_len > 0) {
                        processLine(ctx, line_buf[0..line_len]);
                        line_len = 0;
                    }
                } else if (line_len < line_buf.len) {
                    line_buf[line_len] = byte;
                    line_len += 1;
                }
            }
        }
    }
}

fn processLine(ctx: *Context, line: []const u8) void {
    const result = patterns.parseLine(line) orelse return;
    var ev = SSHEvent{ .backend = .logfile };
    ev.timestamp = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
    ev.event_type = result.event_type;
    ev.setUsername(result.username);
    if (result.pid) |pid| ev.pid = pid;
    if (result.port) |ps| ev.source_port = std.fmt.parseInt(u16, ps, 10) catch 0;
    ip.parseIPInto(result.ip, &ev.source_ip);
    ev.session_id = ev.pid;
    ctx.emit(ev);
}
