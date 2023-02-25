const std = @import("std");
const lib = @import("lib.zig");
const str = @import("strings.zig");
const status = @import("status.zig");
const config = @import("config.zig");
const Allocator = std.mem.Allocator;
const log = std.log;

const Actor = @This();

const Impl = ActorImpl;

pub fn eval(allocator: Allocator, w: *lib.HttpResponse, r: *lib.HttpRequest) void {
    Impl.eval(allocator, w, r);
}

const actor_json = @embedFile("actor.json");
const followers_json = @embedFile("followers.json");
const following_json = @embedFile("following.json");

const ActorImpl = struct {
    fn eval(allocator: Allocator, w: *lib.HttpResponse, req: *lib.HttpRequest) void {
        if (req.method == 1) return status.nomethod(w);

        w.headers.put("Content-Type", "application/json") catch {
            log.err(" response header", .{});
        };
        w.headers.put("Access-Control-Allow-Origin", "*") catch {
            log.err(" response header", .{});
        };

        // ask host for actor setting
        const who = config.SelfActor() orelse "00000";

        const branch = unknownActor(allocator, req.uri, who) catch {
            log.err("allocPrint, OutOfMem", .{});
            return status.internal(w);
        };
        switch (branch) {
            .actor => w.body.appendSlice(actor_json) catch {
                log.err("actor, OutOfMem", .{});
                return status.internal(w);
            },

            .followers => w.body.appendSlice(followers_json) catch {
                log.err("followers, OutOfMem", .{});
                return status.internal(w);
            },

            .following => w.body.appendSlice(following_json) catch {
                log.err("following, OutOfMem", .{});
                return status.internal(w);
            },

            .empty => return status.notfound(w),
        }

        status.ok(w);
    }
};

// "static" actor has limited formats
fn unknownActor(allocator: Allocator, ur: []const u8, who: []const u8) !FormatOption {
    var upath = str.toPath(ur);

    // request for actor
    const base = try std.fmt.allocPrint(allocator, "/u/{s}", .{who});
    defer allocator.free(base);
    if (std.mem.eql(u8, upath, base)) {
        return FormatOption.actor;
    }

    // request for their followers
    const flow = try std.fmt.allocPrint(allocator, "{s}/followers", .{base});
    defer allocator.free(flow);
    if (std.mem.startsWith(u8, upath, flow)) {
        return FormatOption.followers;
    }

    // request for who-they-follow
    const fwng = try std.fmt.allocPrint(allocator, "{s}/following", .{base});
    defer allocator.free(fwng);
    if (std.mem.startsWith(u8, upath, fwng)) {
        return FormatOption.following;
    }

    return FormatOption.empty;
}

const FormatOption = enum { empty, actor, followers, following };
