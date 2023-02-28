const std = @import("std");
const lib = @import("lib.zig");
const str = @import("strings.zig");
const status = @import("status.zig");
const config = @import("config.zig");
const redis = @import("redis.zig");
const signature = @import("signature.zig");
const Allocator = std.mem.Allocator;
const log = std.log;

const Inbox = @This();

const Impl = InboxImpl;

pub fn eval(allocator: Allocator, w: *lib.HttpResponse, r: *lib.HttpRequest) void {
    Impl.eval(allocator, w, r);
}

const InboxImpl = struct {
    fn eval(allocator: Allocator, w: *lib.HttpResponse, req: *lib.HttpRequest) void {
        const bad = unknownSignature(allocator, req);
        if (bad) {
            return status.forbidden(w);
        }

        //TODO limit body content to 1MB
        var tree = str.toTree(allocator, req.body) catch {
            log.err("unexpected json format\n", .{});
            return status.unprocessable(w);
        };
        defer tree.deinit();

        // capture for now (build processing later)
        ////redis.enqueue(allocator, logev) catch {
        redis.debugDetail(allocator, .{ .tree = tree, .req = req }) catch {
            log.err("save failed", .{});
            return status.internal(w);
        };

        w.headers.put("Content-Type", "application/json") catch {
            log.err("response header, OutOfMem", .{});
        };

        status.ok(w);
    }
};

////const MakeKey = fn (uri: []const u8) std.crypto.sign.sha256.PublicKey;
fn unknownSignature(allocator: Allocator, req: *lib.HttpRequest) bool {
    const bad = true;

    var result = signature.calculate(allocator, .{
        .public = true,
        .key = MockKey,
        .request = req,
    }) catch {
        log.err("calculate failed", .{});
        return bad;
    };

    log.debug("calc public, {s}\n", .{result});

    return !bad;
}

fn MockKey(proxy: []const u8) u8 {
    log.debug("mock fetch, {s}\n", .{proxy});
    return 0;
}
