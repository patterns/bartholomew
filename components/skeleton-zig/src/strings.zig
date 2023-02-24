const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;

// convenience routine for transforming request body into JSON tree
pub fn toTree(allocator: Allocator, ls: std.ArrayList(u8)) error{Malformed}!std.json.ValueTree {
    const sane_json = std.json.validate(ls.items);
    if (!sane_json) return error.Malformed;
    var parser = std.json.Parser.init(allocator, false);
    defer parser.deinit();
    var tree = parser.parse(ls.items) catch return error.Malformed;
    return tree;
}

// convenience routine for extracting query params
pub fn toPairs(allocator: Allocator, ur: []const u8) std.StringHashMap([]const u8) {
    var params = std.StringHashMap([]const u8).init(allocator);
    errdefer params.deinit();
    // expect /path?field1=val1&field2=val2

    var start: usize = undefined;
    if (mem.indexOf(u8, ur, "?")) |index| {
        // index inclusive (so +1 to skip '?')
        start = index + 1;
    } else {
        return params;
    }

    var remain = ur[start..ur.len];
    if (!mem.containsAtLeast(u8, remain, 1, "&")) {
        // possibly one/single pair
        if (toKeyVal(remain)) |kv| {
            addParam(allocator, &params, kv) catch {
                std.debug.panic("FAIL pair OutOfMem", .{});
            };
        }
        return params;
    }

    var iter = mem.split(u8, remain, "&");
    while (iter.next()) |pair| {
        var arr: [2][]const u8 = undefined;
        if (toKeyVal(pair)) |kv| {
            arr = kv;
        } else {
            std.debug.print("WARN unexpected param format: {s}\n", .{pair});
            break;
        }
        addParam(allocator, &params, arr) catch {
            std.debug.panic("FAIL params put", .{});
            break;
        };

        //const key = allocator.dupe(u8, arr[0]) catch {
        //    std.debug.panic("FAIL params key", .{});
        //    break;
        //};
        //const val = allocator.dupe(u8, arr[1]) catch {
        //    std.debug.panic("FAIL params val", .{});
        //    break;
        //};
        //params.put(key, val) catch {
        //    std.debug.panic("FAIL params put", .{});
        //    break;
        //};
    }

    // add tests (multiple 'resource' results in last one)
    return params;
}

// take 'field1=val1' and return {field1, val1}
fn toKeyVal(remain: []const u8) ?[2][]const u8 {
    const sz = remain.len;
    var div: usize = undefined;
    if (mem.indexOf(u8, remain, "=")) |index| {
        div = index;
    } else {
        return null;
    }
    const key = remain[0..div];
    const val = remain[(div + 1)..sz];
    std.debug.print("DEBUG k/v, {s} / {s}\n", .{ key, val });

    //TODO ?should this be a struct
    var arr = [2][]const u8{ key, val };

    return arr;
}
fn addParam(allocator: Allocator, m: *std.StringHashMap([]const u8), kv: [2][]const u8) !void {
    const key = allocator.dupe(u8, kv[0]) catch |err| {
        std.debug.panic("FAIL params key", .{});
        return err;
    };
    const val = allocator.dupe(u8, kv[1]) catch |err| {
        std.debug.panic("FAIL params val", .{});
        return err;
    };
    m.put(key, val) catch |err| {
        std.debug.panic("FAIL params put", .{});
        return err;
    };
}

// compare strings (case/everything must match)
pub fn eq(comptime s1: []const u8, s2: []const u8) bool {
    return mem.eql(u8, s1, s2);
}

pub const JsonError = error{Malformed};
