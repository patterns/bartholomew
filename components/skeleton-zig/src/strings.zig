const std = @import("std");

const sdk = @cImport({
    @cInclude("stddef.h");
    @cInclude("spin-http.h");
});
const status = @import("status.zig");

pub fn pairs(al: std.mem.Allocator, req: *sdk.spin_http_request_t) std.StringHashMap([]const u8) {
    // notes - not meant as general headers container and
    //         only want specific items (Signature, Content-Type, Digest)
    // TODO encapsulate map to handle deinit and release k/v items
    //      (need to track clist in order to free later)
    const clist: sdk.spin_http_headers_t = req.headers;
    const sz = clist.len;
    const many: [*c]sdk.spin_http_tuple2_string_string_t = clist.ptr;

    var hm = std.StringHashMap([]const u8).init(al);
    for (many[0..sz]) |tuple| {
        const key: []const u8 = std.mem.span(tuple.f0.ptr);
        const val: []const u8 = std.mem.span(tuple.f1.ptr);

        ////if (eq("signature", key) or eq("content-type", key)) {
        hm.put(key, val) catch std.debug.print("FAIL HashMap, {s}", .{key});
        ////}
    }

    return hm;
}

// request to JSON tree
//pub fn toTree(req: *sdk.spin_http_request_t) std.json.ValueTree {
//    const sz = req.body.val.len;
//    var json_body = std.ArrayList(u8).init(gpal);
//    defer json_body.deinit();
//    json_body.appendSlice(req.body.val.ptr[0..sz]) catch return status.noaccept(res);
//    const sane_json = std.json.validate(json_body.items);
//    if (!sane_json) return status.unprocessable(res);
//    var parser = std.json.Parser.init(gpal, false);
//    defer parser.deinit();
//    var tree = parser.parse(json_body.items) catch return status.expectation(res);
//    defer tree.deinit();
//}

pub fn eq(comptime s1: []const u8, s2: []const u8) bool {
    return std.mem.eql(u8, s1, s2);
}
