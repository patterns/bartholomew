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
        if (req.method == 1) return status.nomethod(w);

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
    var match = false;
    var map = str.toPairs(allocator, ur);
    defer map.deinit();

    if (map.get("resource")) |target| {
        var re = formatResource(allocator) catch {
            log.err("resource list OutOfMem\n", .{});
            return false;
        };
        defer re.deinit();
        const allowed = re.items;

        for (allowed) |known| {
            if (std.mem.eql(u8, target, known)) {
                match = true;
                break;
            }
        }
    }

    return !match;
}

// list allowed resource values
fn formatResource(allocator: Allocator) !std.ArrayList([]const u8) {
    var all = std.ArrayList([]const u8).init(allocator);
    errdefer all.deinit();

    const who = config.SelfActor() orelse "00000";
    const subd = config.SiteSubdomain() orelse "00000";

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
