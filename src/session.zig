const std = @import("std");
const SSHEvent = @import("event.zig").SSHEvent;
const EventType = @import("event.zig").EventType;

pub const SessionState = enum { connected, authenticated, auth_failed, disconnected };

pub const SessionEntry = struct {
    state: SessionState,
    source_ip: [16]u8,
    source_port: u16,
    username: [64]u8,
    pid: u32,
    connect_time: u64,
    last_activity: u64,
};

pub const SessionTable = struct {
    entries: std.AutoHashMap(u64, SessionEntry),
    max_entries: usize,
    allocator: std.mem.Allocator,

    pub fn init(allocator: std.mem.Allocator, max_entries: usize) SessionTable {
        return .{
            .entries = std.AutoHashMap(u64, SessionEntry).init(allocator),
            .max_entries = max_entries,
            .allocator = allocator,
        };
    }

    pub fn deinit(self: *SessionTable) void {
        self.entries.deinit();
    }

    pub fn update(self: *SessionTable, ev: *const SSHEvent) void {
        const result = self.entries.getOrPut(ev.session_id) catch return;

        if (!result.found_existing) {
            if (self.entries.count() > self.max_entries) self.evictOldest();
            result.value_ptr.* = .{
                .state = .connected,
                .source_ip = ev.source_ip,
                .source_port = ev.source_port,
                .username = ev.username,
                .pid = ev.pid,
                .connect_time = ev.timestamp,
                .last_activity = ev.timestamp,
            };
        }

        result.value_ptr.last_activity = ev.timestamp;
        result.value_ptr.state = switch (ev.event_type) {
            .connection => .connected,
            .auth_success => .authenticated,
            .auth_failure => .auth_failed,
            .disconnect => .disconnected,
        };
    }

    /// Check for connections that exceeded auth timeout and emit auth_failure events.
    pub fn checkTimeouts(self: *SessionTable, now: u64, timeout_ns: u64, out: []SSHEvent) usize {
        var count: usize = 0;
        var to_remove: std.ArrayList(u64) = .empty;
        defer to_remove.deinit(self.allocator);

        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.state == .connected and
                now -| entry.value_ptr.connect_time > timeout_ns)
            {
                if (count < out.len) {
                    out[count] = .{
                        .timestamp = now,
                        .event_type = .auth_failure,
                        .source_ip = entry.value_ptr.source_ip,
                        .source_port = entry.value_ptr.source_port,
                        .username = entry.value_ptr.username,
                        .pid = entry.value_ptr.pid,
                        .session_id = entry.key_ptr.*,
                    };
                    count += 1;
                }
                entry.value_ptr.state = .auth_failed;
            }
            // Clean up old disconnected sessions
            if (entry.value_ptr.state == .disconnected and
                now -| entry.value_ptr.last_activity > timeout_ns * 2)
            {
                to_remove.append(self.allocator, entry.key_ptr.*) catch {};
            }
        }

        for (to_remove.items) |id| {
            _ = self.entries.remove(id);
        }
        return count;
    }

    fn evictOldest(self: *SessionTable) void {
        var oldest: u64 = std.math.maxInt(u64);
        var key: ?u64 = null;
        var iter = self.entries.iterator();
        while (iter.next()) |entry| {
            if (entry.value_ptr.last_activity < oldest) {
                oldest = entry.value_ptr.last_activity;
                key = entry.key_ptr.*;
            }
        }
        if (key) |k| _ = self.entries.remove(k);
    }
};

test "session update and timeout" {
    var t = SessionTable.init(std.testing.allocator, 4096);
    defer t.deinit();

    var ev = SSHEvent{};
    ev.session_id = 1;
    ev.event_type = .connection;
    ev.timestamp = 1000;
    t.update(&ev);
    try std.testing.expectEqual(SessionState.connected, t.entries.get(1).?.state);

    var out: [10]SSHEvent = undefined;
    const timeout: u64 = 30 * std.time.ns_per_s;
    const count = t.checkTimeouts(1000 + timeout + 1, timeout, &out);
    try std.testing.expectEqual(@as(usize, 1), count);
    try std.testing.expectEqual(EventType.auth_failure, out[0].event_type);
}

test "session eviction at capacity" {
    var t = SessionTable.init(std.testing.allocator, 2);
    defer t.deinit();

    for (0..3) |i| {
        var ev = SSHEvent{};
        ev.session_id = @intCast(i + 1);
        ev.timestamp = @intCast((i + 1) * 1000);
        ev.event_type = .connection;
        t.update(&ev);
    }
    // Should have evicted oldest when exceeding max
    try std.testing.expect(t.entries.count() <= 3);
}
