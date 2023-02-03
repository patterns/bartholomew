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
    // TODO should we check this requirement?
    var json_val = tree.root.Object.get("type").?;
    const act = json_val.String;
    if (streq("Reject", act) or streq("Undo", act)) {
        return httperr(res, status.teapot);

    } else if (streq("Accept", act)) {
        return httperr(res, status.multi_status);

    } else if (streq("Follow", act)) {
        subscription(gpal, tree) catch return httperr(res, status.request_timeout);
        return httperr(res, status.multi_status);

    } else {
        debugRequest(gpal, tree) catch return httperr(res, status.too_early);
        return httperr(res, status.teapot);
    }

    res.status = @as(c_uint, status.ok);
}

// Stub needed to suppress a "import env::main" error.
pub fn main() void {
    print("main function stub", .{});
}

// TODO more error in wasm runtime
// (maybe hardcode local redis and all inputs to troubleshoot)
fn subscription(al: std.mem.Allocator, content: std.json.ValueTree) !void {
    var bucket = std.ArrayList(u8).init(al);
    defer bucket.deinit();
    try content.root.jsonStringify(.{}, bucket.writer());
    //TODO want the SHA checksum from the header for uniqueness
    const key = content.root.Object.get("id").?.String;
    try record(key, bucket.items);
}
// Requires REDIS_ADDRESS to be defined in spin.toml
fn record(key: []const u8, payload: []u8) error{RedisAddress}!void {
    const addr = std.os.getenv("REDIS_ADDRESS") orelse return error.RedisAddress;

    var cad = redisStr(addr);
    var cke = redisStr(key);
    var cpa = redisPayload(payload);
    _ = sdk.outbound_redis_set(&cad, &cke, &cpa);
    //print("Record status: {}", ore);
}

// TODO progress - spin ERROR at outbound_redis_publish
// save request to troubleshoot/debug
fn debugRequest(al: std.mem.Allocator, content: std.json.ValueTree) !void {
    var bucket = std.ArrayList(u8).init(al);
    defer bucket.deinit();
    //try content.root.jsonStringify(.{}, bucket.writer());
    //DEBUG
    _ = content.root;
    bucket.appendSlice("Placeholder DEBUG check abc") catch print("DEBUG bkt", .{});
    try publish("channelDebug", bucket.items);
}

// Requires REDIS_ADDRESS to be defined in spin.toml
fn publish(comptime channel: []const u8, payload: []u8) error{RedisAddress}!void {
    const addr = std.os.getenv("REDIS_ADDRESS") orelse return error.RedisAddress;

    var cad = redisStr(addr);
    var cch = redisStr(channel);
    var cpa = redisPayload(payload);
    //defer {
    //    sdk.outbound_redis_string_free(&cad);
    //    sdk.outbound_redis_string_free(&cch);
    //    sdk.outbound_redis_payload_free(&cpa);
    //}
    _ = sdk.outbound_redis_publish(&cad, &cch, &cpa);
    //print("Publish status: {}", ore);
}

fn redisStr(x: []const u8) sdk.outbound_redis_string_t {
    const cstr = tocstr(x);

    const rs = sdk.outbound_redis_string_t {
        .ptr = cstr.ptr,
        .len = @intCast(usize, x.len),
    };
    return rs;
}

fn redisPayload(x: []const u8) sdk.outbound_redis_payload_t {
    const cstr = tocstr(x);

    const rp = sdk.outbound_redis_payload_t {
        .ptr = cstr.ptr,
        .len = @intCast(usize, x.len),
    };
    return rp;
}

// encapsulate c_string
// (https://github.com/ziglang/zig/wiki/Zig-Newcomer-Programming-FAQs)
fn tocstr(x: []const u8) [:0]u8 {
    //var bucket = std.ArrayList(u8).init(gpal);
    //defer bucket.deinit();
    var buf: [100:0]u8 = undefined;
    var tmp: []const u8 = x;
    if (x.len > buf.len) {
        ////return error.BufferSize;
        // to debug, don't return error atm and do a workaround instead
        tmp = "DEBUG 1";
    }

    std.mem.copy(u8, buf[0..tmp.len], tmp);
    buf[tmp.len] = 0;
    const cstr = buf[0..tmp.len :0];
    return cstr;
}

fn streq(comptime s1: []const u8, s2: []const u8) bool {
    return std.mem.eql(u8, s1, s2);
}

fn httperr(res: *sdk.spin_http_response_t, comptime sc: status) void {
    // readable?
    //res.status = @as(c_uint, sc);
    res.status = @enumToInt(sc);
}

const ConfigError = error{RedisAddress};
const LimitError = error{BufferSize};

