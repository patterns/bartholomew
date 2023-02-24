const std = @import("std");
const lib = @import("lib.zig");
const str = @import("strings.zig");
const status = @import("status.zig");
const Allocator = std.mem.Allocator;

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
            std.debug.print("ERROR response header", .{});
        };
        w.headers.put("Access-Control-Allow-Origin", "*") catch {
            std.debug.print("ERROR response header", .{});
        };
        w.body.appendSlice(webfinger_json) catch {
            std.debug.print("ERROR webfinger body", .{});
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
            std.debug.print("ERROR resource list OutOfMem\n", .{});
            return false;
        };
        defer re.deinit();
        const allowed = re.items;

        for (allowed) |known| {
            std.debug.print("DEBUG compare, {s} {s}\n", .{ target, known });
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
    const who = std.os.getenv("SELF_ACTOR") orelse "00000";
    const subd = std.os.getenv("SITE_NAME") orelse "00000";

    //case "acct:self@subd":
    const c1 = try std.fmt.allocPrint(allocator, "acct:{s}@{s}.fermyon.app", .{ who, subd });
    try all.append(c1);

    return all;
}
