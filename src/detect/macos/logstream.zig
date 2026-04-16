const std = @import("std");
const posix = std.posix;
const SSHEvent = @import("../../event.zig").SSHEvent;
const Context = @import("../backend.zig").Context;
const patterns = @import("../patterns.zig");
const ip = @import("../ip.zig");

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| {
        std.log.err("logstream backend: {}", .{err});
    };
}

fn runImpl(ctx: *Context) !void {
    var attempt: u8 = 0;
    while (attempt < 3 and !ctx.stopped()) : (attempt += 1) {
        if (attempt > 0) {
            std.log.warn("logstream: respawning log stream (attempt {d})", .{attempt + 1});
            std.Thread.sleep(5 * std.time.ns_per_s);
        }
        spawnAndRead(ctx) catch |err| {
            std.log.err("logstream: log stream exited: {}", .{err});
            continue;
        };
        return;
    }
    std.log.err("logstream: giving up after {d} attempts", .{attempt});
}

fn spawnAndRead(ctx: *Context) !void {
    var child = std.process.Child.init(
        &.{ "log", "stream", "--process", "sshd", "--style", "compact", "--level", "info" },
        std.heap.page_allocator,
    );
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    defer {
        _ = child.kill() catch {};
        _ = child.wait() catch {};
    }

    const stdout = child.stdout orelse return error.NoStdout;
    var pollfds = [_]posix.pollfd{.{ .fd = stdout.handle, .events = posix.POLL.IN, .revents = 0 }};
    var line_buf: [4096]u8 = undefined;
    var line_len: usize = 0;
    var read_buf: [4096]u8 = undefined;

    while (!ctx.stopped()) {
        const ready = posix.poll(&pollfds, 500) catch 0;
        if (ready == 0) continue;

        const n = stdout.read(&read_buf) catch return error.ReadFailed;
        if (n == 0) return error.EndOfStream;

        for (read_buf[0..n]) |byte| {
            if (byte == '\n') {
                if (line_len > 0) {
                    processLine(ctx, line_buf[0..line_len]);
                    line_len = 0;
                }
            } else if (line_len < line_buf.len) {
                line_buf[line_len] = byte;
                line_len += 1;
            } else {
                line_len = 0;
            }
        }
    }
}

fn processLine(ctx: *Context, line: []const u8) void {
    // Strip macOS `log stream` timestamp prefix by locating the sshd marker.
    // Supports both legacy sshd[PID] and modern sshd-session[PID] forms.
    const marker = std.mem.indexOf(u8, line, "sshd-session[") orelse
        std.mem.indexOf(u8, line, "sshd[") orelse return;
    const sshd_line = line[marker..];

    const result = patterns.parseLine(sshd_line) orelse return;

    var ev = SSHEvent{ .backend = .logstream };
    ev.timestamp = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
    ev.event_type = result.event_type;
    ev.setUsername(result.username);
    if (result.pid) |pid| {
        ev.pid = pid;
        ev.session_id = pid;
    }
    ip.parseIPInto(result.ip, &ev.source_ip);
    if (result.port) |port_str| {
        ev.source_port = std.fmt.parseInt(u16, port_str, 10) catch 0;
    }
    ctx.emit(ev);
}
