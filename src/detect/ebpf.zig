const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const EventType = @import("../event.zig").EventType;
const Context = @import("backend.zig").Context;

const c = @cImport({
    @cInclude("bpf/libbpf.h");
    @cInclude("bpf/bpf.h");
});

/// Must match struct ssh_event in bpf/ssh_monitor.h exactly.
const BpfEvent = extern struct {
    timestamp: u64,
    event_type: u32,
    pid: u32,
    ppid: u32,
    source_port: u16,
    dest_port: u16,
    source_ip4: [4]u8,
    comm: [16]u8,
};

var global_ctx: ?*Context = null;

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| {
        std.log.err("ebpf backend: {}", .{err});
    };
}

fn runImpl(ctx: *Context) !void {
    global_ctx = ctx;
    defer global_ctx = null;

    const obj = c.bpf_object__open("zig-out/bpf/ssh_monitor.bpf.o") orelse {
        std.log.err("ebpf: failed to open BPF object at zig-out/bpf/ssh_monitor.bpf.o", .{});
        return error.Unexpected;
    };
    defer c.bpf_object__close(obj);

    if (c.bpf_object__load(obj) != 0) {
        std.log.err("ebpf: failed to load BPF programs", .{});
        return error.Unexpected;
    }

    // Attach all BPF programs
    var prog: ?*c.bpf_program = null;
    while (true) {
        prog = c.bpf_object__next_program(obj, prog);
        if (prog == null) break;
        const link = c.bpf_program__attach(prog);
        if (link == null) {
            const name_ptr = c.bpf_program__name(prog);
            const name_str = if (name_ptr != null) std.mem.sliceTo(name_ptr, 0) else "unknown";
            std.log.err("ebpf: failed to attach program {s}", .{name_str});
            return error.Unexpected;
        }
    }

    // Find the ring buffer map
    const rb_map = c.bpf_object__find_map_by_name(obj, "events") orelse {
        std.log.err("ebpf: 'events' map not found", .{});
        return error.Unexpected;
    };
    const rb_fd = c.bpf_map__fd(rb_map);
    if (rb_fd < 0) return error.Unexpected;

    const rb = c.ring_buffer__new(rb_fd, &handleEvent, null, null) orelse {
        std.log.err("ebpf: failed to create ring buffer", .{});
        return error.Unexpected;
    };
    defer c.ring_buffer__free(rb);

    std.log.info("ebpf: attached, listening on port {d}", .{ctx.config.ssh_port});

    while (!ctx.stopped()) {
        _ = c.ring_buffer__poll(rb, 100);
    }
}

fn handleEvent(_: ?*anyopaque, data: ?*anyopaque, _: usize) callconv(.c) c_int {
    const bpf_ev: *const BpfEvent = @ptrCast(@alignCast(data orelse return 0));
    const ctx = global_ctx orelse return 0;

    var ev = SSHEvent{};
    ev.timestamp = bpf_ev.timestamp;
    ev.event_type = switch (bpf_ev.event_type) {
        0 => EventType.connection,
        1 => EventType.auth_success,
        2 => EventType.auth_failure,
        3 => EventType.disconnect,
        else => return 0,
    };
    ev.pid = bpf_ev.pid;
    ev.session_id = bpf_ev.pid;
    ev.source_port = bpf_ev.source_port;

    // Map IPv4 bytes into IPv4-mapped-IPv6 format
    ev.source_ip = [_]u8{0} ** 16;
    ev.source_ip[10] = 0xff;
    ev.source_ip[11] = 0xff;
    ev.source_ip[12] = bpf_ev.source_ip4[0];
    ev.source_ip[13] = bpf_ev.source_ip4[1];
    ev.source_ip[14] = bpf_ev.source_ip4[2];
    ev.source_ip[15] = bpf_ev.source_ip4[3];

    ctx.emit(ev);
    return 0;
}
