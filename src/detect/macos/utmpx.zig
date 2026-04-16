const std = @import("std");
const SSHEvent = @import("../../event.zig").SSHEvent;
const Context = @import("../backend.zig").Context;
const ip = @import("../ip.zig");

const c = @cImport({
    @cInclude("utmpx.h");
});

const MAX_SESSIONS = 64;
const POLL_INTERVAL_NS = 2 * std.time.ns_per_s;

pub fn run(ctx: *Context) void {
    var known: [MAX_SESSIONS]u32 = [_]u32{0} ** MAX_SESSIONS;
    var known_count: usize = 0;

    while (!ctx.stopped()) {
        var current: [MAX_SESSIONS]u32 = [_]u32{0} ** MAX_SESSIONS;
        var current_count: usize = 0;

        c.setutxent();
        while (c.getutxent()) |entry| {
            if (entry.*.ut_type != c.USER_PROCESS) continue;
            const host = std.mem.sliceTo(&entry.*.ut_host, 0);
            if (host.len == 0) continue; // local console login, not remote SSH

            const pid: u32 = @intCast(entry.*.ut_pid);
            if (current_count < MAX_SESSIONS) {
                current[current_count] = pid;
                current_count += 1;
            }

            var already_known = false;
            for (known[0..known_count]) |k| {
                if (k == pid) {
                    already_known = true;
                    break;
                }
            }
            if (already_known) continue;

            var ev = SSHEvent{ .backend = .utmpx_bsd };
            ev.event_type = .auth_success;
            ev.pid = pid;
            ev.session_id = pid;
            ev.setUsername(std.mem.sliceTo(&entry.*.ut_user, 0));
            ev.timestamp = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
            // ut_host may be a hostname or dotted-quad. parseIPInto handles
            // non-numeric input by producing 0.0.0.0 (harmless fallback).
            ip.parseIPInto(host, &ev.source_ip);
            ctx.emit(ev);
        }
        c.endutxent();

        // Detect disconnects: pids we saw before but are gone now.
        for (known[0..known_count]) |k| {
            var still_here = false;
            for (current[0..current_count]) |cur_pid| {
                if (cur_pid == k) {
                    still_here = true;
                    break;
                }
            }
            if (still_here) continue;

            var ev = SSHEvent{ .backend = .utmpx_bsd };
            ev.event_type = .disconnect;
            ev.pid = k;
            ev.session_id = k;
            ev.timestamp = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
            ctx.emit(ev);
        }

        known = current;
        known_count = current_count;

        std.Thread.sleep(POLL_INTERVAL_NS);
    }
}
