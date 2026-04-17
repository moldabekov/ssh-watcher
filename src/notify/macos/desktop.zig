const std = @import("std");
const posix = std.posix;
const SSHEvent = @import("../../event.zig").SSHEvent;
const Config = @import("../../config.zig").Config;
const template = @import("../../template.zig");
const sink = @import("../sink.zig");

/// Absolute path avoids PATH-planting attacks: osascript is at this location
/// on every supported macOS release. Never resolve via PATH from a root
/// LaunchDaemon whose env we don't fully control.
const OSASCRIPT_BIN = "/usr/bin/osascript";

/// Minimum gap between two successive notification spawns. An attacker can
/// trigger hundreds of failed-auth events per second; without this throttle
/// each one would fork an osascript process, producing a noisy notification
/// storm. First event per window still fires; additional ones are dropped
/// until the cooldown elapses.
const NOTIFY_COOLDOWN_NS: i128 = 200 * std.time.ns_per_ms;

/// Max time we wait for an osascript child to finish before killing it.
/// osascript can hang indefinitely when the user session is in a weird
/// state (TCC prompt with no UI to respond). Keeping this tight protects
/// the sink thread from stalling and letting the ring lap.
const OSASCRIPT_TIMEOUT_NS: u64 = 3 * std.time.ns_per_s;

/// Retry probeOsascript this often if the initial probe fails. macOS
/// LaunchDaemons start before any user session, so the first probe often
/// fails even on a healthy system. Retry periodically so we light up once
/// someone logs in.
const REPROBE_INTERVAL_NS: i128 = 60 * std.time.ns_per_s;

pub fn run(ctx: *sink.SinkContext) void {
    var ready = probeOsascript();
    var next_reprobe: i128 = if (ready) 0 else std.time.nanoTimestamp() + REPROBE_INTERVAL_NS;
    if (!ready) {
        std.log.warn("desktop: osascript probe failed (no user session?); will retry every {d}s", .{
            @divTrunc(REPROBE_INTERVAL_NS, std.time.ns_per_s),
        });
    } else {
        // `display notification` sourced from osascript appears in macOS
        // Notification Center as "Script Editor", not "ssh-watcher" — this
        // is a platform limit of the AppleScript path. A companion
        // LaunchAgent per-user is required for proper branding.
        std.log.info("desktop: notifications will appear as 'Script Editor' in Notification Center", .{});
    }

    var last_notify_ns: i128 = 0;

    while (!ctx.stopped()) {
        if (!ready) {
            const now = std.time.nanoTimestamp();
            if (now >= next_reprobe) {
                ready = probeOsascript();
                if (ready) {
                    std.log.info("desktop: osascript now available, enabling notifications", .{});
                } else {
                    next_reprobe = now + REPROBE_INTERVAL_NS;
                }
            }
            std.Thread.sleep(500 * std.time.ns_per_ms);
            continue;
        }

        if (ctx.consumer.pop()) |ev| {
            if (!sink.shouldNotify(ctx.config, ev.event_type)) continue;
            const now = std.time.nanoTimestamp();
            if (now - last_notify_ns < NOTIFY_COOLDOWN_NS) continue;
            last_notify_ns = now;
            sendNotification(ctx.config, &ev);
        } else {
            std.Thread.sleep(50 * std.time.ns_per_ms);
        }
    }
}

/// Probe once at startup: run `osascript -e "return 1"` and check exit status.
/// Detects both missing binary and missing user-session context (LaunchDaemon
/// without a logged-in user cannot display notifications).
fn probeOsascript() bool {
    var child = std.process.Child.init(
        &.{ OSASCRIPT_BIN, "-e", "return 1" },
        std.heap.page_allocator,
    );
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return false;
    const term = waitWithTimeout(&child, OSASCRIPT_TIMEOUT_NS) orelse {
        std.log.debug("desktop: probe osascript timed out", .{});
        return false;
    };
    return switch (term) {
        .Exited => |code| code == 0,
        else => false,
    };
}

fn sendNotification(config: *const Config, ev: *const SSHEvent) void {
    var title_buf: [256]u8 = undefined;
    var body_buf: [512]u8 = undefined;
    const title = template.expand(config.title_template, ev, &title_buf) catch "SSH Event";
    const body = template.expand(config.body_template, ev, &body_buf) catch "unknown";

    var esc_title_buf: [512]u8 = undefined;
    var esc_body_buf: [1024]u8 = undefined;
    const esc_title = escapeAppleScript(title, &esc_title_buf);
    const esc_body = escapeAppleScript(body, &esc_body_buf);

    var script_buf: [2048]u8 = undefined;
    const script = std.fmt.bufPrint(&script_buf, "display notification \"{s}\" with title \"{s}\"", .{
        esc_body, esc_title,
    }) catch return;

    // page_allocator matches the Linux sibling; Child.init holds the allocator
    // for argv/env duplication during spawn() and small pipe bookkeeping.
    // Allocations are small and short-lived.
    var child = std.process.Child.init(
        &.{ OSASCRIPT_BIN, "-e", script },
        std.heap.page_allocator,
    );
    child.stdin_behavior = .Ignore;
    child.stdout_behavior = .Ignore;
    child.stderr_behavior = .Ignore;
    child.spawn() catch return;

    const term = waitWithTimeout(&child, OSASCRIPT_TIMEOUT_NS) orelse {
        std.log.debug("desktop: osascript timed out after {d}ns; killed", .{OSASCRIPT_TIMEOUT_NS});
        return;
    };
    switch (term) {
        .Exited => |code| if (code != 0) {
            std.log.debug("desktop: osascript exited with code {d}", .{code});
        },
        else => std.log.debug("desktop: osascript terminated abnormally: {}", .{term}),
    }
}

/// Non-blocking wait loop. Polls waitpid(WNOHANG) until the child exits
/// or timeout_ns elapses. On timeout, sends SIGKILL and reaps. Returns the
/// actual Term on clean exit, or null on timeout (child was killed).
fn waitWithTimeout(child: *std.process.Child, timeout_ns: u64) ?std.process.Child.Term {
    const pid = child.id;
    const poll_ns: u64 = 50 * std.time.ns_per_ms;
    var waited: u64 = 0;
    while (waited < timeout_ns) {
        const res = posix.waitpid(pid, std.posix.W.NOHANG);
        if (res.pid != 0) {
            const term = decodeStatus(res.status);
            child.term = term;
            return term;
        }
        std.Thread.sleep(poll_ns);
        waited += poll_ns;
    }
    // Timed out — hard kill and reap.
    _ = posix.kill(pid, posix.SIG.KILL) catch {};
    const res = posix.waitpid(pid, 0);
    child.term = decodeStatus(res.status);
    return null;
}

fn decodeStatus(status: u32) std.process.Child.Term {
    // POSIX status encoding: low byte = signal or 0, next byte = exit code.
    const low: u8 = @truncate(status & 0x7f);
    const high: u8 = @truncate((status >> 8) & 0xff);
    if (low == 0) return .{ .Exited = high };
    if (low == 0x7f) return .{ .Stopped = high };
    return .{ .Signal = low };
}

/// Escape AppleScript string-literal metacharacters. {username} and IP
/// fields come from attacker-controlled SSH data, so we must defend
/// against quote/backslash injection and strip control chars that
/// could disrupt the `osascript -e` command line.
fn escapeAppleScript(input: []const u8, buf: []u8) []const u8 {
    var i: usize = 0;
    for (input) |ch| {
        if (i >= buf.len) break;
        if (ch == '"' or ch == '\\') {
            if (i + 2 > buf.len) break;
            buf[i] = '\\';
            i += 1;
            buf[i] = ch;
            i += 1;
        } else if (ch == '\n' or ch == '\r' or ch == '\t') {
            buf[i] = ' ';
            i += 1;
        } else if (ch >= 0x20 and ch != 0x7f) {
            buf[i] = ch;
            i += 1;
        }
        // else: drop control char
    }
    return buf[0..i];
}

test "escapeAppleScript doubles quotes" {
    var buf: [64]u8 = undefined;
    const out = escapeAppleScript("hello \"world\"", &buf);
    try std.testing.expectEqualStrings("hello \\\"world\\\"", out);
}

test "escapeAppleScript doubles backslashes" {
    var buf: [64]u8 = undefined;
    const out = escapeAppleScript("a\\b", &buf);
    try std.testing.expectEqualStrings("a\\\\b", out);
}

test "escapeAppleScript replaces newlines with spaces" {
    var buf: [64]u8 = undefined;
    const out = escapeAppleScript("line1\nline2\r\nline3\tend", &buf);
    try std.testing.expectEqualStrings("line1 line2  line3 end", out);
}

test "escapeAppleScript drops control chars" {
    var buf: [64]u8 = undefined;
    const out = escapeAppleScript("a\x00b\x07c\x1fd\x7fe", &buf);
    try std.testing.expectEqualStrings("abcde", out);
}

test "escapeAppleScript respects buf overflow" {
    var buf: [4]u8 = undefined;
    const out = escapeAppleScript("\"\"\"", &buf);
    try std.testing.expectEqualStrings("\\\"\\\"", out);
}

test "escapeAppleScript preserves UTF-8" {
    var buf: [64]u8 = undefined;
    const out = escapeAppleScript("héllo \xf0\x9f\x8c\x8d", &buf);
    try std.testing.expectEqualStrings("héllo \xf0\x9f\x8c\x8d", out);
}

test "escapeAppleScript empty input" {
    var buf: [16]u8 = undefined;
    try std.testing.expectEqualStrings("", escapeAppleScript("", &buf));
}

test "escapeAppleScript exact fit" {
    var buf: [3]u8 = undefined;
    try std.testing.expectEqualStrings("abc", escapeAppleScript("abc", &buf));
}
