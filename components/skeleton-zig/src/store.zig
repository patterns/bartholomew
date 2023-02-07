const std = @import("std");
const sdk = @cImport({
    @cInclude("stddef.h");
    @cInclude("outbound-redis.h");
});

// add *job* item that will be picked up by a *worker*
pub fn enqueue(al: std.mem.Allocator, content: std.json.ValueTree) !void {
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

    saveEvent(caddr, ckey, cpayload);
}

// invoke the sdk with args in "C" form
fn saveEvent(addr: [:0]u8, key: [:0]u8, payload: [:0]u8) void {
    var ad = sdk.outbound_redis_string_t{ .ptr = addr.ptr, .len = addr.len };
    var ke = sdk.outbound_redis_string_t{ .ptr = key.ptr, .len = key.len };
    var pa = sdk.outbound_redis_payload_t{ .ptr = payload.ptr, .len = payload.len };

    //TODO learn how to handle the error struct
    _ = sdk.outbound_redis_set(&ad, &ke, &pa);
}

// troubleshoot request body & headers
// (notification that needs attention)
pub fn alarm(al: std.mem.Allocator, ls: *std.ArrayList(u8), m: std.StringHashMap([]const u8)) !void {
    try ls.appendSlice(";DEBUG headers DEBUG; ");
    var iterator = m.iterator();
    while (iterator.next()) |entry| {
        try ls.writer().print("{s}:{s}, ", .{ entry.key_ptr.*, entry.value_ptr.* });
    }
    return broadcast(al, "channelDebug", ls.items);
}

pub fn broadcast(al: std.mem.Allocator, channel: []const u8, buf: []u8) !void {
    // duplicate list to sentinel-terminated
    const cstr = try al.dupeZ(u8, buf);
    defer al.free(cstr);

    // duplicate channel to sentinel-terminated
    const cch = try al.dupeZ(u8, channel);
    defer al.free(cch);

    // duplicate REDIS_ADDRESS to sentinel-terminated
    const addr: []const u8 = std.os.getenv("REDIS_ADDRESS") orelse "redis://127.0.0.1:6379";
    const caddr = try al.dupeZ(u8, addr);
    defer al.free(caddr);

    broadcastEvent(caddr, cch, cstr);
}

// invoke the sdk with args in "C" form
fn broadcastEvent(addr: [:0]u8, channel: [:0]u8, payload: [:0]u8) void {
    var ad = sdk.outbound_redis_string_t{ .ptr = addr.ptr, .len = addr.len };
    var ch = sdk.outbound_redis_string_t{ .ptr = channel.ptr, .len = channel.len };
    var pa = sdk.outbound_redis_payload_t{ .ptr = payload.ptr, .len = payload.len };

    //TODO learn how to handle the error struct
    _ = sdk.outbound_redis_publish(&ad, &ch, &pa);
}
