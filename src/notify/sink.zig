const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const EventType = @import("../event.zig").EventType;
const Config = @import("../config.zig").Config;
const BroadcastBuffer = @import("../ring_buffer.zig").BroadcastBuffer;

pub const SinkContext = struct {
    consumer: BroadcastBuffer(SSHEvent).Consumer,
    config: *const Config,
    should_stop: *std.atomic.Value(bool),

    pub fn stopped(self: *SinkContext) bool {
        return self.should_stop.load(.acquire);
    }
};

pub fn shouldNotify(config: *const Config, event_type: EventType) bool {
    return switch (event_type) {
        .connection => config.notify_on_connection,
        .auth_success => config.notify_on_auth_success,
        .auth_failure => config.notify_on_auth_failure,
        .disconnect => config.notify_on_disconnect,
    };
}

test "shouldNotify" {
    const config = Config{};
    try std.testing.expect(!shouldNotify(&config, .connection));
    try std.testing.expect(shouldNotify(&config, .auth_success));
    try std.testing.expect(shouldNotify(&config, .auth_failure));
    try std.testing.expect(!shouldNotify(&config, .disconnect));
}
