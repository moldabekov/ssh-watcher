const std = @import("std");
const SSHEvent = @import("../../event.zig").SSHEvent;
const Context = @import("../backend.zig").Context;

// TODO: Verify libbsm API (au_read_rec, au_fetch_tok, au_print_tok) on
// macOS 14+ before enabling. /dev/auditpipe access requires root and
// may be restricted by SIP; test with an explicit audit_control(5)
// configuration.
// const c = @cImport({ @cInclude("bsm/libbsm.h"); });

pub fn run(ctx: *Context) void {
    std.log.err("audit_bsm: OpenBSM backend not yet implemented; use 'logstream' instead", .{});
    while (!ctx.stopped()) {
        std.Thread.sleep(1 * std.time.ns_per_s);
    }
}
