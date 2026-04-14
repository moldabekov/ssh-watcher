const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const Context = @import("backend.zig").Context;
const patterns = @import("patterns.zig");
const logfile = @import("logfile.zig");

const c = @cImport({
    @cInclude("systemd/sd-journal.h");
});

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| {
        std.log.err("journal backend: {}", .{err});
    };
}

fn runImpl(ctx: *Context) !void {
    var journal: ?*c.sd_journal = null;
    if (c.sd_journal_open(&journal, c.SD_JOURNAL_LOCAL_ONLY) < 0)
        return error.Unexpected;
    defer c.sd_journal_close(journal);

    // Filter by _COMM=sshd-session to catch both the main sshd.service
    // and per-session scopes (session-N.scope) which carry disconnect messages
    if (c.sd_journal_add_match(journal, "_COMM=sshd-session", 18) < 0)
        return error.Unexpected;

    // Seek to tail — only process new messages
    if (c.sd_journal_seek_tail(journal) < 0)
        return error.Unexpected;
    _ = c.sd_journal_previous(journal);

    while (!ctx.stopped()) {
        const wait_rc = c.sd_journal_wait(journal, 1000 * 1000);
        if (wait_rc < 0) continue;
        if (wait_rc == c.SD_JOURNAL_NOP) continue;

        while (c.sd_journal_next(journal) > 0) {
            var msg_data: [*c]const u8 = undefined;
            var msg_len: usize = 0;
            if (c.sd_journal_get_data(journal, "MESSAGE", @ptrCast(&msg_data), &msg_len) < 0) continue;

            // Extract PID from _PID journal field
            var pid_data: [*c]const u8 = undefined;
            var pid_len: usize = 0;
            var pid: u32 = 0;
            if (c.sd_journal_get_data(journal, "_PID", @ptrCast(&pid_data), &pid_len) >= 0) {
                const pid_full = pid_data[0..pid_len];
                if (std.mem.indexOf(u8, pid_full, "=")) |eq| {
                    pid = std.fmt.parseInt(u32, pid_full[eq + 1 ..], 10) catch 0;
                }
            }

            // MESSAGE=<actual message>
            const msg_full = msg_data[0..msg_len];
            if (std.mem.indexOf(u8, msg_full, "=")) |eq_pos| {
                processMessage(ctx, msg_full[eq_pos + 1 ..], pid);
            }
        }
    }
}

fn processMessage(ctx: *Context, msg: []const u8, journal_pid: u32) void {
    const result = patterns.parseLine(msg) orelse return;
    var ev = SSHEvent{ .backend = .journal };
    ev.timestamp = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
    ev.event_type = result.event_type;
    ev.setUsername(result.username);
    // Prefer PID from journal field; fall back to parsing from message
    ev.pid = if (journal_pid != 0) journal_pid else (result.pid orelse 0);
    if (result.port) |ps| ev.source_port = std.fmt.parseInt(u16, ps, 10) catch 0;
    logfile.parseIPInto(result.ip, &ev.source_ip);
    ev.session_id = ev.pid;
    ctx.emit(ev);
}
