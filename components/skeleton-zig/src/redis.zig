const std = @import("std");
const config = @import("config.zig");
const log = std.log;

// add _job_ item that will be picked up by a _worker_
pub fn enqueue(allocator: std.mem.Allocator, content: std.json.ValueTree) !void {
    var bucket = std.ArrayList(u8).init(allocator);
    defer bucket.deinit();
    try content.root.jsonStringify(.{}, bucket.writer());

    // duplicate payload to sentinel-terminated
    const cpayload = try allocator.dupeZ(u8, bucket.items);
    defer allocator.free(cpayload);

    //TODO want the SHA checksum from the header for uniqueness
    //     (also needs sanity check / guard)
    // duplicate id to sentinel-terminated
    const key = content.root.Object.get("id").?.String;
    const ckey = try allocator.dupeZ(u8, key);
    defer allocator.free(ckey);

    // duplicate redis address to sentinel-terminated
    const addr: []const u8 = config.redisAddress() orelse "redis://127.0.0.1:6379";
    const caddr = try allocator.dupeZ(u8, addr);
    defer allocator.free(caddr);

    saveEvent(caddr, ckey, cpayload);
}

// capture extra request detail to debug/tests
pub fn debugDetail(ally: std.mem.Allocator, option: anytype) !void {
    const tree = option.tree;
    const req = option.req;

    var bucket = std.ArrayList(u8).init(ally);
    defer bucket.deinit();
    try tree.root.jsonStringify(.{}, bucket.writer());
    try bucket.appendSlice("##DEBUG##");

    var rownum: usize = 0;
    while (rownum < req.headers.len) : (rownum += 1) {
        const tup = req.headers[rownum];
        if (tup.fld.len == 0) break;
        try bucket.writer().print(";{s}#{s}", .{ tup.fld, tup.val });
    }

    // duplicate payload to sentinel-terminated
    const cpayload = try ally.dupeZ(u8, bucket.items);
    defer ally.free(cpayload);

    // duplicate id to sentinel-terminated
    const key = tree.root.Object.get("id").?.String;
    const ckey = try ally.dupeZ(u8, key);
    defer ally.free(ckey);

    // duplicate redis address to sentinel-terminated
    const addr: []const u8 = config.redisAddress() orelse "redis://127.0.0.1:6379";
    const caddr = try ally.dupeZ(u8, addr);
    defer ally.free(caddr);

    saveEvent(caddr, ckey, cpayload);
}

/////////////////////////////////////////////////////////////
// WASI C/interop

// (see https://github.com/ziglang/zig/issues/2274)
pub extern "outbound-redis" fn set(i32, i32, i32, i32, i32, i32, i32) void;
pub extern "outbound-redis" fn publish(i32, i32, i32, i32, i32, i32, i32) void;

var RET_AREA: [16]u8 align(8) = std.mem.zeroes([16]u8);

fn saveEvent(redis: [:0]u8, key: [:0]u8, value: [:0]u8) void {
    var result: i32 = @intCast(i32, @ptrToInt(&RET_AREA));

    // ask the host
    set(@intCast(i32, @ptrToInt(redis.ptr)), @bitCast(i32, redis.len), @intCast(i32, @ptrToInt(key.ptr)), @bitCast(i32, key.len), @intCast(i32, @ptrToInt(value.ptr)), @bitCast(i32, value.len), result);

    const errcode = @intCast(usize, @intToPtr([*c]u8, @intCast(usize, result)).*);
    if (errcode == 0) {
        // zero means ok
        log.debug("redis set done, {s}\n", .{key});
    } else {
        // error (more detail hydration todo)
        log.err("redis set failed", .{});
    }
}
