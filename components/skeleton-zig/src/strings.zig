const std = @import("std");
const mem = std.mem;
const log = std.log;
const Allocator = mem.Allocator;

// convenience routine for transforming request body into JSON tree
pub fn toTree(ally: Allocator, ls: *std.io.FixedBufferStream([]u8)) !std.json.ValueTree {
    var rd = ls.reader();
    // TODO not using stream and assuming small body
    var bb = try rd.readBoundedBytes(1024);
    const body = bb.constSlice();

    const sane_json = std.json.validate(body);
    if (!sane_json) return error.Malformed;
    var parser = std.json.Parser.init(ally, false);
    defer parser.deinit();
    var tree = parser.parse(body) catch return error.Malformed;
    return tree;
}

// extract path from request
pub fn toPath(ur: []const u8) []const u8 {
    // expect /path?...
    var delim: usize = undefined;
    if (mem.indexOf(u8, ur, "?")) |index| {
        delim = index;
    } else {
        delim = ur.len;
    }
    const left = ur[0..delim];

    return left;
}

// convenience routine for extracting query params
pub fn qryParams(allocator: Allocator, txt: []const u8) std.StringHashMap([]const u8) {
    // expect /path?field1=val1&field2=val2
    var start: usize = undefined;

    if (mem.indexOf(u8, txt, "?")) |index| {
        // index inclusive (so +1 to skip '?')
        start = index + 1;
    } else {
        // ?should we use error type here
        return std.StringHashMap([]const u8).init(allocator);
    }

    var remain = txt[start..txt.len];
    return txtPairs(allocator, .{
        .data = remain,
        .delim = "&",
        .trim = null,
    });
}

// DEPRECATE
//fn sigPairs(allocator: Allocator, raw: []const u8) std.StringHashMap([]const u8) {
//    const discard: ?[]const u8 = "\"";
//    return txtPairs(allocator, .{
//        .data = raw,
//        .delim = ",",
//        .trim = discard,
//    });
//}

fn txtPairs(allocator: Allocator, option: anytype) std.StringHashMap([]const u8) {
    const data: []const u8 = option.data;
    const delim: []const u8 = option.delim;

    // expect field1=val1<delim>field2=val2

    var params = std.StringHashMap([]const u8).init(allocator);
    errdefer params.deinit();

    if (!mem.containsAtLeast(u8, data, 1, delim)) {
        // possibly one/single pair
        if (toKeyVal(data, option)) |kv| {
            addParam(allocator, &params, kv) catch {
                std.debug.panic("FAIL pair OutOfMem", .{});
            };
        }
        return params;
    }

    var iter = mem.split(u8, data, delim);
    while (iter.next()) |pair| {
        var arr: [2][]const u8 = undefined;
        if (toKeyVal(pair, option)) |kv| {
            arr = kv;
        } else {
            log.warn("unexpected param format: {s}", .{pair});
            break;
        }
        addParam(allocator, &params, arr) catch {
            std.debug.panic("FAIL params put", .{});
            break;
        };
    }

    // add tests (multiple 'resource' results in last one)
    return params;
}

// take 'field1=val1' and return {field1, val1}
fn toKeyVal(remain: []const u8, option: anytype) ?[2][]const u8 {
    const sz = remain.len;
    var div: usize = undefined;
    if (mem.indexOf(u8, remain, "=")) |index| {
        div = index;
    } else {
        return null;
    }
    const key = remain[0..div];
    const val = remain[(div + 1)..sz];
    var cleaned = val;

    if (option.trim) |discard| {
        cleaned = std.mem.trim(u8, val, discard);
    }

    //TODO ?should this be a struct
    var arr = [2][]const u8{ key, cleaned };

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

pub fn percentDecode(allocator: Allocator, ur: []const u8) ![]const u8 {
    // plus symbol means space
    // %nn is ASCII hex val prefixed by percent symbol
    // e.g.,replacing %40 with '@' means shrinking width by 2
    const shrink = 2;

    var count: usize = 0;
    var total: usize = 0;
    const max = mem.replacementSize(u8, ur, "+", " ");
    var acc = try allocator.alloc(u8, max);
    defer allocator.free(acc);
    var tmp = try allocator.alloc(u8, max);
    defer allocator.free(tmp);

    // mutate plus symbols
    count = mem.replace(u8, ur, "+", " ", acc);
    log.debug("+ replaced, {d}", .{count});
    total += count;

    var percent: usize = max;
    if (mem.indexOf(u8, acc, "%")) |index| {
        percent = index;
    }
    while (percent != max) {
        const old = acc[percent .. percent + 3];
        const new = fmtAscii(old);
        log.debug("replacing, {s} with {s}", .{ old, new });
        log.debug("before, {s}", .{acc});

        count = mem.replace(u8, acc, old, new, tmp);
        mem.copy(u8, acc, tmp);

        total += count * shrink;
        log.debug("after, {s} {d}", .{ acc, count });
        if (mem.indexOf(u8, acc, "%")) |index| {
            percent = index;
        } else {
            break;
        }
    }

    // trim empty bytes
    log.debug("empties (to chop),  {d}", .{total});
    const shrunk_size = max - total;
    return std.fmt.allocPrint(allocator, "{s}", .{acc[0..shrunk_size]});
}

fn fmtAscii(from: []const u8) []const u8 {
    const eq = std.ascii.eqlIgnoreCase;
    // TODO refactor

    if (eq("%3A", from)) return ":";
    if (eq("%2F", from)) return "/";
    if (eq("%3F", from)) return "?";
    if (eq("%23", from)) return "#";
    if (eq("%5B", from)) return "[";
    if (eq("%5D", from)) return "]";
    if (eq("%40", from)) return "@";
    if (eq("%21", from)) return "!";
    if (eq("%24", from)) return "$";
    if (eq("%26", from)) return "&";
    if (eq("%27", from)) return "'";
    if (eq("%28", from)) return "(";
    if (eq("%29", from)) return ")";
    if (eq("%2A", from)) return "*";
    if (eq("%2B", from)) return "+";
    if (eq("%2C", from)) return ",";
    if (eq("%3B", from)) return ";";
    if (eq("%3D", from)) return "=";
    if (eq("%20", from)) return " ";

    //TODO use a placeholder to do a second pass in order to prevent infinite loop
    //if eq("%25", from) return "[Z]";

    // unecessary encodes
    return from;
}

pub const JsonError = error{Malformed};
