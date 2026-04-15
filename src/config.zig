const std = @import("std");

pub const Backend = enum {
    auto,
    ebpf,
    journal,
    logfile,
    utmp,

    pub fn fromString(s: []const u8) !Backend {
        if (std.mem.eql(u8, s, "auto")) return .auto;
        if (std.mem.eql(u8, s, "ebpf")) return .ebpf;
        if (std.mem.eql(u8, s, "journal")) return .journal;
        if (std.mem.eql(u8, s, "logfile")) return .logfile;
        if (std.mem.eql(u8, s, "utmp")) return .utmp;
        return error.InvalidValue;
    }
};

pub const Urgency = enum {
    low,
    normal,
    critical,

    pub fn fromString(s: []const u8) !Urgency {
        if (std.mem.eql(u8, s, "low")) return .low;
        if (std.mem.eql(u8, s, "normal")) return .normal;
        if (std.mem.eql(u8, s, "critical")) return .critical;
        return error.InvalidValue;
    }
};

pub const WebhookEndpoint = struct {
    url: []const u8 = "",
    timeout_seconds: u32 = 5,
    max_retries: u32 = 3,
    payload_template: ?[]const u8 = null,
};

pub const Config = struct {
    backend: Backend = .auto,
    ssh_port: u16 = 22,
    auth_timeout_seconds: u32 = 30,

    notify_on_connection: bool = false,
    notify_on_auth_success: bool = true,
    notify_on_auth_failure: bool = true,
    notify_on_disconnect: bool = false,

    desktop_enabled: bool = true,
    urgency_connection: Urgency = .low,
    urgency_success: Urgency = .normal,
    urgency_failure: Urgency = .critical,
    urgency_disconnect: Urgency = .low,
    title_template: []const u8 = "SSH: {event_type}",
    body_template: []const u8 = "{username}@{source_ip}:{source_port}",

    log_enabled: bool = false,
    log_path: []const u8 = "/var/log/ssh-watcher.log",

    webhook_enabled: bool = false,
    endpoints: []WebhookEndpoint = &.{},

    allocator: ?std.mem.Allocator = null,
    /// Raw content buffers whose memory backs string slices in this Config.
    /// Stored here so they are freed when the Config is freed.
    _owned_bufs: [2]?[]const u8 = .{ null, null },

    pub fn ownContent(self: *Config, buf: []const u8) void {
        if (self._owned_bufs[0] == null) {
            self._owned_bufs[0] = buf;
        } else {
            self._owned_bufs[1] = buf;
        }
    }

    pub fn deinit(self: *Config) void {
        if (self.allocator) |alloc| {
            if (self.endpoints.len > 0) alloc.free(self.endpoints);
            for (&self._owned_bufs) |*b| {
                if (b.*) |buf| {
                    alloc.free(buf);
                    b.* = null;
                }
            }
        }
    }
};

const Section = enum { root, detection, events, desktop, log, webhook, webhook_endpoint };

pub const ParseError = error{
    InvalidValue,
    InvalidSection,
    InvalidFormat,
    Overflow,
    InvalidCharacter,
    OutOfMemory,
};

pub fn parse(allocator: std.mem.Allocator, content: []const u8) ParseError!Config {
    var config = Config{};
    config.allocator = allocator;
    var section: Section = .root;
    var endpoints: std.ArrayList(WebhookEndpoint) = .empty;

    var line_iter = std.mem.splitScalar(u8, content, '\n');
    while (line_iter.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;

        if (std.mem.startsWith(u8, line, "[[")) {
            const end = std.mem.indexOf(u8, line, "]]") orelse return error.InvalidSection;
            const name = std.mem.trim(u8, line[2..end], " ");
            if (std.mem.eql(u8, name, "webhook.endpoints")) {
                try endpoints.append(allocator, .{});
                section = .webhook_endpoint;
            } else return error.InvalidSection;
        } else if (line[0] == '[') {
            const end = std.mem.indexOfScalar(u8, line, ']') orelse return error.InvalidSection;
            const name = std.mem.trim(u8, line[1..end], " ");
            if (std.mem.eql(u8, name, "detection")) section = .detection
            else if (std.mem.eql(u8, name, "events")) section = .events
            else if (std.mem.eql(u8, name, "desktop")) section = .desktop
            else if (std.mem.eql(u8, name, "log")) section = .log
            else if (std.mem.eql(u8, name, "webhook")) section = .webhook
            else return error.InvalidSection;
        } else {
            const eq_pos = std.mem.indexOfScalar(u8, line, '=') orelse return error.InvalidFormat;
            const key = std.mem.trim(u8, line[0..eq_pos], " \t");
            const raw_val = std.mem.trim(u8, line[eq_pos + 1 ..], " \t");
            const val = stripQuotes(raw_val);
            try applyValue(&config, section, &endpoints, key, val);
        }
    }

    if (endpoints.items.len > 0) {
        config.endpoints = try endpoints.toOwnedSlice(allocator);
    } else {
        endpoints.deinit(allocator);
    }
    return config;
}

fn applyValue(config: *Config, section: Section, endpoints: *std.ArrayList(WebhookEndpoint), key: []const u8, val: []const u8) ParseError!void {
    switch (section) {
        .detection => {
            if (eq(key, "backend")) config.backend = try Backend.fromString(val)
            else if (eq(key, "ssh_port")) config.ssh_port = try std.fmt.parseInt(u16, val, 10)
            else if (eq(key, "auth_timeout_seconds")) config.auth_timeout_seconds = try std.fmt.parseInt(u32, val, 10);
        },
        .events => {
            if (eq(key, "notify_on_connection")) config.notify_on_connection = parseBool(val)
            else if (eq(key, "notify_on_auth_success")) config.notify_on_auth_success = parseBool(val)
            else if (eq(key, "notify_on_auth_failure")) config.notify_on_auth_failure = parseBool(val)
            else if (eq(key, "notify_on_disconnect")) config.notify_on_disconnect = parseBool(val);
        },
        .desktop => {
            if (eq(key, "enabled")) config.desktop_enabled = parseBool(val)
            else if (eq(key, "urgency_connection")) config.urgency_connection = try Urgency.fromString(val)
            else if (eq(key, "urgency_success")) config.urgency_success = try Urgency.fromString(val)
            else if (eq(key, "urgency_failure")) config.urgency_failure = try Urgency.fromString(val)
            else if (eq(key, "urgency_disconnect")) config.urgency_disconnect = try Urgency.fromString(val)
            else if (eq(key, "title_template")) config.title_template = val
            else if (eq(key, "body_template")) config.body_template = val;
        },
        .log => {
            if (eq(key, "enabled")) config.log_enabled = parseBool(val)
            else if (eq(key, "path")) config.log_path = val;
        },
        .webhook => {
            if (eq(key, "enabled")) config.webhook_enabled = parseBool(val);
        },
        .webhook_endpoint => {
            if (endpoints.items.len == 0) return;
            const ep = &endpoints.items[endpoints.items.len - 1];
            if (eq(key, "url")) ep.url = val
            else if (eq(key, "timeout_seconds")) ep.timeout_seconds = try std.fmt.parseInt(u32, val, 10)
            else if (eq(key, "max_retries")) ep.max_retries = try std.fmt.parseInt(u32, val, 10)
            else if (eq(key, "payload_template")) ep.payload_template = val;
        },
        .root => {},
    }
}

fn stripQuotes(s: []const u8) []const u8 {
    if (s.len >= 2 and ((s[0] == '"' and s[s.len - 1] == '"') or (s[0] == '\'' and s[s.len - 1] == '\'')))
        return s[1 .. s.len - 1];
    return s;
}

fn parseBool(s: []const u8) bool {
    return std.mem.eql(u8, s, "true");
}

fn eq(a: []const u8, b: []const u8) bool {
    return std.mem.eql(u8, a, b);
}

pub fn loadFile(allocator: std.mem.Allocator, path: []const u8) ![]const u8 {
    const file = try std.fs.openFileAbsolute(path, .{});
    defer file.close();
    return try file.readToEndAlloc(allocator, 1024 * 1024);
}

pub fn mergeConfigs(base: Config, over: Config) Config {
    var m = base;
    m.notify_on_connection = over.notify_on_connection;
    m.notify_on_auth_success = over.notify_on_auth_success;
    m.notify_on_auth_failure = over.notify_on_auth_failure;
    m.notify_on_disconnect = over.notify_on_disconnect;
    m.desktop_enabled = over.desktop_enabled;
    m.urgency_connection = over.urgency_connection;
    m.urgency_success = over.urgency_success;
    m.urgency_failure = over.urgency_failure;
    m.urgency_disconnect = over.urgency_disconnect;
    m.title_template = over.title_template;
    m.body_template = over.body_template;
    m.log_enabled = over.log_enabled;
    m.webhook_enabled = over.webhook_enabled;
    if (over.backend != .auto) m.backend = over.backend;
    if (over.ssh_port != 22) m.ssh_port = over.ssh_port;
    if (over.auth_timeout_seconds != 30) m.auth_timeout_seconds = over.auth_timeout_seconds;
    if (!std.mem.eql(u8, over.log_path, "/var/log/ssh-watcher.log")) m.log_path = over.log_path;
    if (over.endpoints.len > 0) m.endpoints = over.endpoints;
    return m;
}

test "parse minimal config" {
    var config = try parse(std.testing.allocator,
        \\[detection]
        \\backend = "ebpf"
        \\ssh_port = 2222
        \\
        \\[events]
        \\notify_on_connection = true
    );
    defer config.deinit();
    try std.testing.expectEqual(Backend.ebpf, config.backend);
    try std.testing.expectEqual(@as(u16, 2222), config.ssh_port);
    try std.testing.expect(config.notify_on_connection);
    try std.testing.expect(config.notify_on_auth_success);
}

test "parse webhook endpoints" {
    var config = try parse(std.testing.allocator,
        \\[webhook]
        \\enabled = true
        \\
        \\[[webhook.endpoints]]
        \\url = "https://hooks.slack.com/test"
        \\timeout_seconds = 10
        \\
        \\[[webhook.endpoints]]
        \\url = "https://discord.com/api/webhooks/test"
    );
    defer config.deinit();
    try std.testing.expect(config.webhook_enabled);
    try std.testing.expectEqual(@as(usize, 2), config.endpoints.len);
    try std.testing.expectEqualStrings("https://hooks.slack.com/test", config.endpoints[0].url);
}

test "parse comments and empty lines" {
    var config = try parse(std.testing.allocator,
        \\# comment
        \\
        \\[detection]
        \\backend = "journal"
    );
    defer config.deinit();
    try std.testing.expectEqual(Backend.journal, config.backend);
}

test "defaults" {
    var config = try parse(std.testing.allocator, "");
    defer config.deinit();
    try std.testing.expectEqual(Backend.auto, config.backend);
    try std.testing.expectEqual(@as(u16, 22), config.ssh_port);
    try std.testing.expect(config.notify_on_auth_success);
    try std.testing.expect(!config.notify_on_connection);
    try std.testing.expect(config.desktop_enabled);
    try std.testing.expect(!config.log_enabled);
}
