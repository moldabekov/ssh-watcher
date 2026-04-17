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
            if (checkPath(MACOS_LOG_BIN)) return .logstream;
            if (req == .logstream) return null;
        }
        if (req == .audit_bsm) {
            // The OpenBSM backend is a stub (needs real-macOS API verification).
            // Returning null here prevents a user who explicitly selected it
            // from ending up with a daemon that silently emits zero events.
            std.log.err("audit_bsm backend is not yet implemented; use 'logstream'", .{});
            return null;
        }
        if (req == .utmpx_bsd or req == .auto) {
            // Last-resort fallback: utmpx is deprecated on macOS 10.9+ and
            // may produce no events. err-level so operators notice rather
            // than silently running a known-degraded backend.
            std.log.err("utmpx is deprecated on macOS 10.9+ and may produce no events; prefer 'logstream'", .{});
            return .utmpx_bsd;
        }
    }
    return null;
}

// Named constants for probe path checks. Extracted for grep-ability and to
// stay in sync with the actual exec paths used by each backend.
const MACOS_LOG_BIN = "/usr/bin/log";

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
