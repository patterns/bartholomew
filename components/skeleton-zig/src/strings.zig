const std = @import("std");

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
