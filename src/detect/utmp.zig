const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const Context = @import("backend.zig").Context;
const logfile = @import("logfile.zig");

// Native utmp definition — avoids @cImport so musl targets work.
// Layout matches the Linux ABI (glibc/musl compatible, see utmp.h).
const USER_PROCESS = 7;

const Utmp = extern struct {
    ut_type: i16,
    _pad0: [2]u8 = undefined,
    ut_pid: i32,
    ut_line: [32]u8,
    ut_id: [4]u8,
    ut_user: [32]u8,
    ut_host: [256]u8,
    ut_exit: extern struct { e_termination: i16, e_exit: i16 },
    ut_session: i32,
    _pad1: [4]u8 = undefined,
    ut_tv: extern struct { tv_sec: i32, tv_usec: i32 },
    ut_addr_v6: [4]u32,
    _unused: [20]u8,
};

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| {
        std.log.err("utmp backend: {}", .{err});
    };
}

fn runImpl(ctx: *Context) !void {
    var known = std.AutoHashMap(u32, void).init(std.heap.page_allocator);
    defer known.deinit();
    scan(&known, ctx, true);
    while (!ctx.stopped()) {
        std.Thread.sleep(2 * std.time.ns_per_s);
        scan(&known, ctx, false);
    }
}

fn scan(known: *std.AutoHashMap(u32, void), ctx: *Context, initial: bool) void {
    const file = std.fs.openFileAbsolute("/var/run/utmp", .{}) catch return;
    defer file.close();
    var current = std.AutoHashMap(u32, void).init(std.heap.page_allocator);
    defer current.deinit();

    const sz = @sizeOf(Utmp);
    var buf: [sz]u8 align(@alignOf(Utmp)) = undefined;
    while (true) {
        const n = file.read(&buf) catch break;
        if (n < sz) break;
        const entry: *const Utmp = @ptrCast(&buf);
        if (entry.ut_type != USER_PROCESS) continue;
        const pid: u32 = @intCast(entry.ut_pid);
        current.put(pid, {}) catch continue;
        const host = std.mem.sliceTo(&entry.ut_host, 0);
        if (host.len == 0) continue;
        if (!known.contains(pid)) {
            known.put(pid, {}) catch continue;
            if (!initial) {
                var ev = SSHEvent{};
                ev.timestamp = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
                ev.event_type = .auth_success;
                ev.pid = pid;
                ev.session_id = pid;
                ev.setUsername(std.mem.sliceTo(&entry.ut_user, 0));
                logfile.parseIPInto(host, &ev.source_ip);
                ctx.emit(ev);
            }
        }
    }

    // Detect disconnects
    var iter = known.iterator();
    var to_remove: std.ArrayList(u32) = .empty;
    defer to_remove.deinit(std.heap.page_allocator);
    while (iter.next()) |e| {
        if (!current.contains(e.key_ptr.*)) {
            if (!initial) {
                var ev = SSHEvent{};
                ev.timestamp = @intCast(@max(@as(i128, 0), std.time.nanoTimestamp()));
                ev.event_type = .disconnect;
                ev.pid = e.key_ptr.*;
                ev.session_id = e.key_ptr.*;
                ctx.emit(ev);
            }
            to_remove.append(std.heap.page_allocator, e.key_ptr.*) catch {};
        }
    }
    for (to_remove.items) |pid| _ = known.remove(pid);
}
