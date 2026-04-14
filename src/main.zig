const std = @import("std");
pub const event = @import("event.zig");

pub fn main() !void {
    std.debug.print("ssh-notifier v0.1.0\n", .{});
}

test {
    _ = event;
    _ = @import("ring_buffer.zig");
    _ = @import("config.zig");
    _ = @import("template.zig");
    _ = @import("detect/patterns.zig");
    _ = @import("detect/backend.zig");
    _ = @import("detect/logfile.zig");
}
