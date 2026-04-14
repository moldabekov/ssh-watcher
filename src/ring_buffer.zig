const std = @import("std");

pub fn BroadcastBuffer(comptime T: type) type {
    return struct {
        const Self = @This();

        items: []T,
        write_pos: std.atomic.Value(u64),
        capacity: u64,
        allocator: std.mem.Allocator,

        pub fn init(allocator: std.mem.Allocator, requested: usize) !Self {
            const cap = std.math.ceilPowerOfTwo(usize, @max(requested, 2)) catch requested;
            const items = try allocator.alloc(T, cap);
            @memset(std.mem.sliceAsBytes(items), 0);
            return .{
                .items = items,
                .write_pos = std.atomic.Value(u64).init(0),
                .capacity = @intCast(cap),
                .allocator = allocator,
            };
        }

        pub fn deinit(self: *Self) void {
            self.allocator.free(self.items);
        }

        pub fn push(self: *Self, item: T) void {
            const pos = self.write_pos.load(.monotonic);
            self.items[@intCast(pos & (self.capacity - 1))] = item;
            self.write_pos.store(pos +% 1, .release);
        }

        pub fn consumer(self: *Self) Consumer {
            return .{
                .ring = self,
                .read_pos = self.write_pos.load(.acquire),
                .dropped = 0,
            };
        }

        pub const Consumer = struct {
            ring: *Self,
            read_pos: u64,
            dropped: u64,

            pub fn pop(self: *Consumer) ?T {
                const wp = self.ring.write_pos.load(.acquire);
                if (self.read_pos >= wp) return null;

                if (wp - self.read_pos > self.ring.capacity) {
                    const new_pos = wp - self.ring.capacity;
                    self.dropped += new_pos - self.read_pos;
                    self.read_pos = new_pos;
                }

                const item = self.ring.items[@intCast(self.read_pos & (self.ring.capacity - 1))];
                self.read_pos += 1;
                return item;
            }

            pub fn drainAll(self: *Consumer, out: []T) usize {
                var count: usize = 0;
                while (count < out.len) {
                    if (self.pop()) |item| {
                        out[count] = item;
                        count += 1;
                    } else break;
                }
                return count;
            }
        };
    };
}

test "push and pop" {
    var buf = try BroadcastBuffer(u32).init(std.testing.allocator, 4);
    defer buf.deinit();

    var c = buf.consumer();
    buf.push(10);
    buf.push(20);
    buf.push(30);

    try std.testing.expectEqual(@as(?u32, 10), c.pop());
    try std.testing.expectEqual(@as(?u32, 20), c.pop());
    try std.testing.expectEqual(@as(?u32, 30), c.pop());
    try std.testing.expectEqual(@as(?u32, null), c.pop());
}

test "consumer lapping drops events" {
    var buf = try BroadcastBuffer(u32).init(std.testing.allocator, 4);
    defer buf.deinit();

    var c = buf.consumer();
    for (0..6) |i| {
        buf.push(@intCast(i));
    }

    const first = c.pop().?;
    try std.testing.expectEqual(@as(u32, 2), first);
    try std.testing.expectEqual(@as(u64, 2), c.dropped);
}

test "multiple independent consumers" {
    var buf = try BroadcastBuffer(u32).init(std.testing.allocator, 8);
    defer buf.deinit();

    var c1 = buf.consumer();
    var c2 = buf.consumer();

    buf.push(42);

    try std.testing.expectEqual(@as(?u32, 42), c1.pop());
    try std.testing.expectEqual(@as(?u32, 42), c2.pop());
    try std.testing.expectEqual(@as(?u32, null), c1.pop());
    try std.testing.expectEqual(@as(?u32, null), c2.pop());
}

test "drainAll" {
    var buf = try BroadcastBuffer(u32).init(std.testing.allocator, 8);
    defer buf.deinit();

    var c = buf.consumer();
    buf.push(1);
    buf.push(2);
    buf.push(3);

    var out: [10]u32 = undefined;
    const n = c.drainAll(&out);
    try std.testing.expectEqual(@as(usize, 3), n);
    try std.testing.expectEqual(@as(u32, 1), out[0]);
    try std.testing.expectEqual(@as(u32, 2), out[1]);
    try std.testing.expectEqual(@as(u32, 3), out[2]);
}

test "power of two rounding" {
    var buf = try BroadcastBuffer(u8).init(std.testing.allocator, 5);
    defer buf.deinit();
    try std.testing.expectEqual(@as(u64, 8), buf.capacity);
}
