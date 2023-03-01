const std = @import("std");
const lib = @import("lib.zig");
const str = @import("strings.zig");
const status = @import("status.zig");
const config = @import("config.zig");
const Allocator = std.mem.Allocator;
const log = std.log;

const Webfinger = @This();

const Impl = WebfingerImpl;

pub fn eval(allocator: Allocator, w: *lib.HttpResponse, r: *lib.HttpRequest) void {
    Impl.eval(allocator, w, r);
}

const webfinger_json = @embedFile("webfinger.json");

const WebfingerImpl = struct {
    fn eval(allocator: Allocator, w: *lib.HttpResponse, req: *lib.HttpRequest) void {
        if (req.method != 0) return status.nomethod(w);

        const unknown = unknownResource(allocator, req.uri);
        if (unknown) return status.bad(w);

        w.headers.put("Content-Type", "application/jrd+json") catch {
            log.err("ERROR response header", .{});
        };
        w.headers.put("Access-Control-Allow-Origin", "*") catch {
            log.err("ERROR response header", .{});
        };
        w.body.appendSlice(webfinger_json) catch {
            log.err("ERROR webfinger body", .{});
            return status.internal(w);
        };

        status.ok(w);
    }
};

// check query param 'resource'
fn unknownResource(allocator: Allocator, ur: []const u8) bool {
    const bad = true;
    var map = str.qryParams(allocator, ur);
    defer map.deinit();

    var resource: []const u8 = undefined;
    if (map.get("resource")) |val| {
        resource = val;
    } else {
        log.err("param resource is required", .{});
        return bad;
    }
    var grp = formatResource(allocator) catch {
        log.err("resource list OutOfMem", .{});
        return bad;
    };
    defer grp.deinit();
    const allowed = grp.items;
    const decoded = str.percentDecode(allocator, resource) catch {
        log.err("decode OutOfMem", .{});
        return bad;
    };
    defer allocator.free(decoded);
    for (allowed) |known| {
        log.debug("cmp {s} ({d}) to {s} ({d})", .{ known, known.len, decoded, decoded.len });

        if (std.mem.eql(u8, known, decoded)) {
            return !bad;
        }
    }

    return bad;
}

// list allowed resource values
fn formatResource(allocator: Allocator) !std.ArrayList([]const u8) {
    var all = std.ArrayList([]const u8).init(allocator);
    errdefer all.deinit();

    const who = config.selfActor() orelse "00000";
    const subd = config.siteSubdomain() orelse "00000";

    //case "acct:self@subd":
    const c1 = try std.fmt.allocPrint(allocator, "acct:{s}@{s}", .{ who, subd });
    try all.append(c1);

    //case "mailto:self@subd"
    const c2 = try std.fmt.allocPrint(allocator, "mailto:{s}@{s}", .{ who, subd });
    try all.append(c2);

    //case "https://subd"
    const c3 = try std.fmt.allocPrint(allocator, "https://{s}", .{subd});
    try all.append(c3);

    //case "https://subd/"
    const c4 = try std.fmt.allocPrint(allocator, "https://{s}/", .{subd});
    try all.append(c4);

    return all;
}
