const std = @import("std");
const print = std.debug.print;
const status = std.http.Status;
const sdk = @cImport({
    @cInclude("stddef.h");
    @cInclude("spin-http.h");
    @cInclude("outbound-redis.h");
});

const Gpa = std.heap.GeneralPurposeAllocator(.{});

// Entry point required by the Spin host.
export fn spin_http_handle_http_request(
        req: *sdk.spin_http_request_t,
        res: *sdk.spin_http_response_t) callconv(.C) void {

    defer sdk.spin_http_request_free(req);

    // TODO restrict path? (or just rely on routing)

    if (req.method != sdk.SPIN_HTTP_METHOD_POST) return httperr(res, status.method_not_allowed);

    // TODO Verify header for Signature and Content-Type

    var gpa = Gpa{};
    defer std.debug.assert(!gpa.deinit());
    const gpal = gpa.allocator();

    var payload = std.ArrayList(u8).init(gpal);
    defer payload.deinit();

    if (req.body.is_some) {
        const sz = req.body.val.len;
        // restrict max to 1MB
        if (sz > 1048576) return httperr(res, status.payload_too_large);

        payload.appendSlice(req.body.val.ptr[0..sz]) catch return httperr(res, status.variant_also_negotiates);
        const sane_json = std.json.validate(payload.items);
        if (!sane_json) return httperr(res, status.not_acceptable);
    }

    var parser = std.json.Parser.init(gpal, false);
    defer parser.deinit();
    var tree = parser.parse(payload.items) catch return httperr(res, status.expectation_failed);
    defer tree.deinit();

    const activity_found = tree.root.Object.contains("type");
    if (!activity_found) return httperr(res, status.failed_dependency);

    // JSON value for the (activity) "type" property must be of string.
    // TODO check this requirement (sanity check / guard)
    var json_val = tree.root.Object.get("type").?;
    const act = json_val.String;
    if (streq("Reject", act) or streq("Undo", act)) {
        captureEvent(gpal, tree) catch return httperr(res, status.request_timeout);

    } else if (streq("Accept", act)) {
        captureEvent(gpal, tree) catch return httperr(res, status.request_timeout);

    } else if (streq("Follow", act)) {
        captureEvent(gpal, tree) catch return httperr(res, status.request_timeout);

    } else {
        broadcast(gpal, "channelDebug", tree) catch return httperr(res, status.too_early);
        return httperr(res, status.no_content);
    }

    httperr(res, status.ok);
}

// Stub needed to suppress a "import env::main" error.
pub fn main() void {
    print("main function stub", .{});
}

fn captureEvent(al: std.mem.Allocator, content: std.json.ValueTree) !void {
    var bucket = std.ArrayList(u8).init(al);
    defer bucket.deinit();
    try content.root.jsonStringify(.{}, bucket.writer());

    // duplicate payload to sentinel-terminated
    const cpayload = try al.dupeZ(u8, bucket.items);
    defer al.free(cpayload);

    //TODO want the SHA checksum from the header for uniqueness 
    //     (also needs sanity check / guard)
    // duplicate id to sentinel-terminated
    const key = content.root.Object.get("id").?.String;
    const ckey = try al.dupeZ(u8, key);
    defer al.free(ckey);

    // duplicate REDIS_ADDRESS to sentinel-terminated
    const addr: []const u8 = std.os.getenv("REDIS_ADDRESS") orelse "redis://127.0.0.1:6379";
    const caddr = try al.dupeZ(u8, addr);
    defer al.free(caddr);

    recordevent(caddr, ckey, cpayload);
}

fn recordevent(addr: [:0]u8, key: [:0]u8, payload: [:0]u8) void {
    var ad = sdk.outbound_redis_string_t { .ptr = addr.ptr, .len = addr.len };
    var ke = sdk.outbound_redis_string_t { .ptr = key.ptr, .len = key.len };
    var pa = sdk.outbound_redis_payload_t { .ptr = payload.ptr, .len = payload.len };

    //TODO learn how to handle the error struct
    _ = sdk.outbound_redis_set(&ad, &ke, &pa);
}

// to troubleshoot/debug
fn broadcast(al: std.mem.Allocator, channel: []const u8, content: std.json.ValueTree) !void {
    var bucket = std.ArrayList(u8).init(al);
    defer bucket.deinit();
    try content.root.jsonStringify(.{}, bucket.writer());

    // duplicate payload to sentinel-terminated
    const cpayload = try al.dupeZ(u8, bucket.items);
    defer al.free(cpayload);

    // duplicate channel to sentinel-terminated
    const cch = try al.dupeZ(u8, channel);
    defer al.free(cch);

    // duplicate REDIS_ADDRESS to sentinel-terminated
    const addr: []const u8 = std.os.getenv("REDIS_ADDRESS") orelse "redis://127.0.0.1:6379";
    const caddr = try al.dupeZ(u8, addr);
    defer al.free(caddr);

    announce(caddr, cch, cpayload);
}

fn announce(addr: [:0]u8, channel: [:0]u8, payload: [:0]u8) void {
    var ad = sdk.outbound_redis_string_t { .ptr = addr.ptr, .len = addr.len };
    var ch = sdk.outbound_redis_string_t { .ptr = channel.ptr, .len = channel.len };
    var pa = sdk.outbound_redis_payload_t { .ptr = payload.ptr, .len = payload.len };

    //TODO learn how to handle the error struct
    _ = sdk.outbound_redis_publish(&ad, &ch, &pa);
}

fn streq(comptime s1: []const u8, s2: []const u8) bool {
    return std.mem.eql(u8, s1, s2);
}

fn httperr(res: *sdk.spin_http_response_t, comptime sc: status) void {
    // readable?
    res.status = @enumToInt(sc);
}

const ConfigError = error{RedisAddress};
const LimitError = error{BufferSize};

