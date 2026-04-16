const std = @import("std");
const builtin = @import("builtin");
const SSHEvent = @import("../event.zig").SSHEvent;
const BroadcastBuffer = @import("../ring_buffer.zig").BroadcastBuffer;
const Config = @import("../config.zig").Config;

const is_linux = builtin.os.tag == .linux;
const is_macos = builtin.os.tag == .macos;

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

pub const BackendType = enum {
    // Linux
    ebpf,
    journal,
    logfile,
    utmp,
    // macOS
    logstream,
    audit_bsm,
    utmpx_bsd,
};

pub fn probe(config: *const Config) ?BackendType {
    const req = config.backend;
    if (is_linux) {
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
    }
    if (is_macos) {
        if (req == .logstream or req == .auto) {
            if (checkPath("/usr/bin/log")) return .logstream;
            if (req == .logstream) return null;
        }
        if (req == .audit_bsm or req == .auto) {
            if (checkPath("/dev/auditpipe")) return .audit_bsm;
            if (req == .audit_bsm) return null;
        }
        if (req == .utmpx_bsd or req == .auto) {
            std.log.warn("utmpx is deprecated on macOS 10.9+, may produce no events", .{});
            return .utmpx_bsd;
        }
    }
    return null;
}

fn checkPath(path: []const u8) bool {
    std.fs.accessAbsolute(path, .{}) catch return false;
    return true;
}

test "probe returns something on this system" {
    const config = Config{};
    if (is_linux or is_macos) {
        try std.testing.expect(probe(&config) != null);
    }
}
