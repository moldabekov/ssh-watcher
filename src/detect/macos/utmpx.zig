const std = @import("std");
const SSHEvent = @import("../../event.zig").SSHEvent;
const Context = @import("../backend.zig").Context;
const ip = @import("../ip.zig");

const c = @cImport({
    @cInclude("utmpx.h");
});

const POLL_INTERVAL_NS = 2 * std.time.ns_per_s;
const SHUTDOWN_CHECK_NS = 250 * std.time.ns_per_ms;

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| {
        std.log.err("utmpx backend: {}", .{err});
    };
}

fn runImpl(ctx: *Context) !void {
    var known = std.AutoHashMap(u32, void).init(std.heap.page_allocator);
    defer known.deinit();

    // Two seed passes 500ms apart: sessions established during the ~2s
    // window between daemon start and the first scheduled scan would
    // otherwise enter `known` via the silent initial pass and never emit
    // auth_success. This is more common on macOS than Linux because
    // LaunchDaemon KeepAlive respawns tend to coincide with logins.
    scan(&known, ctx, true);
    std.Thread.sleep(500 * std.time.ns_per_ms);
    if (ctx.stopped()) return;
    scan(&known, ctx, false);
    while (!ctx.stopped()) {
        // Chunked sleep so shutdown latency stays well under POLL_INTERVAL_NS.
        var waited: u64 = 0;
        while (waited < POLL_INTERVAL_NS and !ctx.stopped()) {
            std.Thread.sleep(SHUTDOWN_CHECK_NS);
            waited += SHUTDOWN_CHECK_NS;
        }
        if (ctx.stopped()) break;
        scan(&known, ctx, false);
    }
}

fn scan(known: *std.AutoHashMap(u32, void), ctx: *Context, initial: bool) void {
    var current = std.AutoHashMap(u32, void).init(std.heap.page_allocator);
    defer current.deinit();

    c.setutxent();
    while (c.getutxent()) |entry| {
        if (entry.*.ut_type != c.USER_PROCESS) continue;

        // Track every USER_PROCESS pid in current BEFORE filtering by host —
        // matches the Linux utmp sibling. Skipping pids with empty host
        // before populating current made them look like disconnects on
        // the next iteration.
        const pid: u32 = @intCast(entry.*.ut_pid);
        current.put(pid, {}) catch continue;

        const host = std.mem.sliceTo(&entry.*.ut_host, 0);
        if (host.len == 0) continue; // local console login without host field

        if (known.contains(pid)) continue;
        known.put(pid, {}) catch continue;
        if (initial) continue;

        var ev = SSHEvent{ .backend = .utmpx_bsd };
        ev.timestamp = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
        ev.event_type = .auth_success;
        ev.pid = pid;
        ev.session_id = pid;
        ev.setUsername(std.mem.sliceTo(&entry.*.ut_user, 0));
        // ut_host may be a hostname or dotted-quad. parseIPInto tolerates
        // non-numeric input by writing 0.0.0.0 (harmless fallback).
        ip.parseIPInto(host, &ev.source_ip);
        ctx.emit(ev);
    }
    c.endutxent();

    // Detect disconnects: pids we tracked that are no longer in the database.
    var to_remove: std.ArrayList(u32) = .empty;
    defer to_remove.deinit(std.heap.page_allocator);
    var iter = known.iterator();
    while (iter.next()) |e| {
        const pid = e.key_ptr.*;
        if (current.contains(pid)) continue;
        if (!initial) {
            var ev = SSHEvent{ .backend = .utmpx_bsd };
            ev.timestamp = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
            ev.event_type = .disconnect;
            ev.pid = pid;
            ev.session_id = pid;
            ctx.emit(ev);
        }
        to_remove.append(std.heap.page_allocator, pid) catch {};
    }
    for (to_remove.items) |pid| _ = known.remove(pid);
}
