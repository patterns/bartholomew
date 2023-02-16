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

// convenience routine for transforming request body into JSON tree
pub fn toTree(al: std.mem.Allocator, ls: std.ArrayList(u8)) error{Malformed}!std.json.ValueTree {
    const sane_json = std.json.validate(ls.items);
    if (!sane_json) return error.Malformed;
    var parser = std.json.Parser.init(al, false);
    defer parser.deinit();
    var tree = parser.parse(ls.items) catch return error.Malformed;
    return tree;
}

// compare strings (case/everything must match)
pub fn eq(comptime s1: []const u8, s2: []const u8) bool {
    return std.mem.eql(u8, s1, s2);
}

pub const JsonError = error{Malformed};
