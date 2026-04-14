const std = @import("std");
const SSHEvent = @import("../event.zig").SSHEvent;
const EventType = @import("../event.zig").EventType;
const Context = @import("backend.zig").Context;

const c = @cImport({
    @cInclude("bpf/libbpf.h");
    @cInclude("bpf/bpf.h");
});

/// Must match struct ssh_event in bpf/ssh_monitor.h (no packed attribute).
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

const MAX_LINKS = 8;

var global_ctx: ?*Context = null;

/// Embedded BPF ELF object — compiled at build time by clang.
const bpf_elf = @embedFile("ssh_monitor.bpf.o");

pub fn run(ctx: *Context) void {
    runImpl(ctx) catch |err| {
        std.log.err("ebpf backend: {}", .{err});
    };
}

fn runImpl(ctx: *Context) !void {
    global_ctx = ctx;
    defer global_ctx = null;

    const obj = c.bpf_object__open_mem(bpf_elf.ptr, bpf_elf.len, null) orelse {
        std.log.err("ebpf: failed to open BPF object from embedded data", .{});
        return error.Unexpected;
    };
    defer c.bpf_object__close(obj);

    // Override target_port from config before loading
    const rodata = c.bpf_object__find_map_by_name(obj, ".rodata");
    if (rodata) |rd| {
        // The .rodata section contains the volatile const target_port (u16 at offset 0)
        var initial_size: usize = 0;
        const initial_ptr = c.bpf_map__initial_value(rd, &initial_size);
        if (initial_ptr != null and initial_size >= 2) {
            const port: u16 = ctx.config.ssh_port;
            const port_bytes = std.mem.asBytes(&port);
            const dest: [*]u8 = @ptrCast(initial_ptr);
            dest[0] = port_bytes[0];
            dest[1] = port_bytes[1];
            std.log.info("ebpf: set target_port={d} in BPF rodata", .{port});
        }
    }

    if (c.bpf_object__load(obj) != 0) {
        std.log.err("ebpf: failed to load BPF programs (kernel BTF or privileges?)", .{});
        return error.Unexpected;
    }

    // Attach all BPF programs, storing links for cleanup
    var links: [MAX_LINKS]?*c.bpf_link = .{null} ** MAX_LINKS;
    var link_count: usize = 0;
    defer {
        for (links[0..link_count]) |maybe_link| {
            if (maybe_link) |link| _ = c.bpf_link__destroy(link);
        }
    }

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
        if (link_count < MAX_LINKS) {
            links[link_count] = link;
            link_count += 1;
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

    std.log.info("ebpf: attached {d} programs, listening on port {d}", .{ link_count, ctx.config.ssh_port });

    while (!ctx.stopped()) {
        const ret = c.ring_buffer__poll(rb, 100);
        if (ret < 0 and ret != -4) { // -4 = EINTR, ignore
            std.log.err("ebpf: ring_buffer__poll error: {d}", .{ret});
        }
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
    // For session correlation: connection events use their own PID,
    // exec/exit events use ppid (the sshd parent) to link back to the connection.
    ev.session_id = if (bpf_ev.ppid != 0) bpf_ev.ppid else bpf_ev.pid;
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
