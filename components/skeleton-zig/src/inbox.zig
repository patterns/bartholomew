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

        // capture for now (build processing later/next)
        ////redis.enqueue(allocator, logev) catch {
        redis.debugDetail(allocator, .{ .tree = tree, .req = req }) catch {
            log.err("save failed", .{});
            return status.internal(w);
        };

        w.headers.put("Content-Type", "application/json") catch {
            log.err("inbox header, OutOfMem", .{});
        };

        status.ok(w);
    }
};

fn unknownSignature(allocator: Allocator, req: *lib.HttpRequest) bool {
    const bad = true;

    var sig = signature.init(allocator, .{ .request = req });
    defer sig.deinit();

    var hashed = sig.calculate(allocator, .{ .request = req }) catch {
        log.err("sha256 failed", .{});
        return bad;
    };

    sig.registerProxy(MockKey);
    const check = sig.verifyPKCS1v15(allocator, hashed);
    log.debug("verify, {any}", .{check});

    // checks passed
    return !bad;
}

// need test cases for the httpsig input sequence
fn MockKey(proxy: []const u8) []const u8 {
    log.debug("mock fetch, {s}\n", .{proxy});
    return "MOCK-PUBKEY";
}
