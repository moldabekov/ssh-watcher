const std = @import("std");
const posix = std.posix;
const SSHEvent = @import("../../event.zig").SSHEvent;
const Context = @import("../backend.zig").Context;
const patterns = @import("../patterns.zig");
const ip = @import("../ip.zig");

const MAX_CONSECUTIVE_FAILURES = 3;
const RESPAWN_DELAY_NS = 5 * std.time.ns_per_s;
const STABLE_RUN_THRESHOLD_NS: i128 = 60 * std.time.ns_per_s;
const POLL_TIMEOUT_MS = 500;

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| {
        std.log.err("logstream backend: {}", .{err});
    };
}

fn runImpl(ctx: *Context) !void {
    var failures: u8 = 0;
    while (failures < MAX_CONSECUTIVE_FAILURES and !ctx.stopped()) {
        if (failures > 0) {
            std.log.warn("logstream: respawning (attempt {d}/{d})", .{
                failures + 1, MAX_CONSECUTIVE_FAILURES,
            });
            std.Thread.sleep(RESPAWN_DELAY_NS);
        }
        const start_ns: i128 = std.time.nanoTimestamp();
        spawnAndRead(ctx) catch |err| {
            const ran_ns = std.time.nanoTimestamp() - start_ns;
            std.log.err("logstream: child exited after {d}s: {}", .{
                @divTrunc(ran_ns, std.time.ns_per_s), err,
            });
            // Reset failure budget if the child ran successfully for a while
            // before dying — otherwise a daemon that runs for months would
            // permanently give up after 3 lifetime hiccups.
            if (ran_ns > STABLE_RUN_THRESHOLD_NS) {
                failures = 0;
            } else {
                failures += 1;
            }
            continue;
        };
        return; // clean shutdown via ctx.stopped()
    }
    if (!ctx.stopped()) {
        std.log.err("logstream: giving up after {d} consecutive failures", .{failures});
    }
}

// Absolute paths avoid PATH-planting attacks: a writable early-PATH entry
// could otherwise replace `log`. /usr/bin/log is shipped with every macOS.
const LOG_BIN = "/usr/bin/log";

fn spawnAndRead(ctx: *Context) !void {
    var child = std.process.Child.init(
        &.{ LOG_BIN, "stream", "--process", "sshd", "--style", "compact", "--level", "info" },
        std.heap.page_allocator,
    );
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Pipe;
    child.stderr_behavior = .Ignore;
    try child.spawn();
    defer _ = child.kill() catch {};

    const stdout = child.stdout orelse return error.NoStdout;
    var pollfds = [_]posix.pollfd{.{ .fd = stdout.handle, .events = posix.POLL.IN, .revents = 0 }};
    var line_buf: [4096]u8 = undefined;
    var line_len: usize = 0;
    var truncated = false;
    var read_buf: [4096]u8 = undefined;

    while (!ctx.stopped()) {
        const ready = posix.poll(&pollfds, POLL_TIMEOUT_MS) catch |err| {
            std.log.err("logstream: poll failed: {}", .{err});
            return error.PollFailed;
        };
        if (ready == 0) continue;

        // Drain readable bytes FIRST — when the child exits after writing its
        // final buffer, both POLLIN and POLLHUP are set, and reacting to HUP
        // before reading would drop the tail of the log.
        const revents = pollfds[0].revents;
        if (revents & posix.POLL.IN != 0) {
            const n = stdout.read(&read_buf) catch return error.ReadFailed;
            if (n == 0) return error.EndOfStream;
            for (read_buf[0..n]) |byte| {
                if (byte == '\n') {
                    if (line_len > 0 and !truncated) {
                        processLine(ctx, line_buf[0..line_len]);
                    }
                    line_len = 0;
                    truncated = false;
                } else if (line_len < line_buf.len) {
                    line_buf[line_len] = byte;
                    line_len += 1;
                } else if (!truncated) {
                    std.log.warn("logstream: line > {d} bytes, dropping", .{line_buf.len});
                    truncated = true;
                }
            }
        }
        const hangup_mask: i16 = posix.POLL.HUP | posix.POLL.ERR | posix.POLL.NVAL;
        if (revents & hangup_mask != 0) return error.ChildHungUp;
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
