const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const BroadcastBuffer = @import("../ring_buffer.zig").BroadcastBuffer;
const Config = @import("../config.zig").Config;

pub const Context = struct {
    ring: *BroadcastBuffer(SSHEvent),
    config: *const Config,
    should_stop: *std.atomic.Value(bool),

    pub fn emit(self: *Context, ev: SSHEvent) void {
        self.ring.push(ev);
    }

    pub fn stopped(self: *Context) bool {
        return self.should_stop.load(.acquire);
    }
};

pub const BackendType = enum { ebpf, journal, logfile, utmp };

pub fn probe(config: *const Config) ?BackendType {
    const req = config.backend;
    if (req == .ebpf or req == .auto) {
        if (checkPath("/sys/kernel/btf/vmlinux")) return .ebpf;
        if (req == .ebpf) return null;
    }
    if (req == .journal or req == .auto) {
        if (checkPath("/run/systemd/system")) return .journal;
        if (req == .journal) return null;
    }
    if (req == .logfile or req == .auto) {
        if (checkPath("/var/log/auth.log") or checkPath("/var/log/secure")) return .logfile;
        if (req == .logfile) return null;
    }
    if (req == .utmp or req == .auto) return .utmp;
    return null;
}

fn checkPath(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

test "probe returns something on this system" {
    const config = Config{};
    try std.testing.expect(probe(&config) != null);
}
