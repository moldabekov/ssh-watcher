const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const Context = @import("backend.zig").Context;
const logfile = @import("logfile.zig");

const c = @cImport({
    @cInclude("utmp.h");
});

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

    const sz = @sizeOf(c.struct_utmp);
    var buf: [sz]u8 align(@alignOf(c.struct_utmp)) = undefined;
    while (true) {
        const n = file.read(&buf) catch break;
        if (n < sz) break;
        const entry: *const c.struct_utmp = @ptrCast(&buf);
        if (entry.ut_type != c.USER_PROCESS) continue;
        const pid: u32 = @intCast(entry.ut_pid);
        current.put(pid, {}) catch continue;
        const host = std.mem.sliceTo(&entry.ut_host, 0);
        if (host.len == 0) continue;
        if (!known.contains(pid)) {
            known.put(pid, {}) catch continue;
            if (!initial) {
                var ev = SSHEvent{};
                ev.timestamp = @intCast(@as(u128, @bitCast(std.time.nanoTimestamp())));
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
                ev.timestamp = @intCast(@as(u128, @bitCast(std.time.nanoTimestamp())));
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
