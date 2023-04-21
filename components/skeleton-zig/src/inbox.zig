const std = @import("std");
const lib = @import("lib.zig");
const str = @import("strings.zig");
const status = @import("status.zig");
const config = @import("config.zig");
const redis = @import("redis.zig");
const vfr = @import("verifier.zig");

const phi = @import("phi.zig");
const Allocator = std.mem.Allocator;
const log = std.log;

const Inbox = @This();

const Impl = InboxImpl;

pub fn eval(ally: Allocator, w: *lib.HttpResponse, r: *lib.SpinRequest) void {
    Impl.eval(ally, w, r);
}

const InboxImpl = struct {
    fn eval(ally: Allocator, w: *lib.HttpResponse, req: *lib.SpinRequest) void {
        const bad = unknownSignature(ally, req.*) catch true;

        if (bad) {
            return status.forbidden(w);
        }

        //TODO limit body content to 1MB
        var tree = str.toTree(ally, req.body) catch {
            log.err("unexpected json format\n", .{});
            return status.unprocessable(w);
        };
        defer tree.deinit();

        // capture for now (build processing later/next)
        ////redis.enqueue(allocator, logev) catch {
        redis.debugDetail(ally, .{ .tree = tree, .req = req }) catch {
            log.err("save failed", .{});
            return status.internal(w);
        };

        w.headers.put("Content-Type", "application/json") catch {
            log.err("inbox header, OutOfMem", .{});
        };

        status.ok(w);
    }
};

fn unknownSignature(ally: Allocator, req: lib.SpinRequest) !bool {
    const bad = true;

    var placeholder: phi.RawHeaders = undefined;
    var wrap = phi.HeaderList.init(ally, placeholder);

    try vfr.init(ally, placeholder);

    var hashed = try vfr.sha256Base(req, wrap);
    vfr.attachFetch(customVerifier);

    _ = try vfr.verify(ally, hashed);

    // checks passed
    return !bad;
}

// need test cases for the httpsig input sequence
fn customVerifier(proxy: []const u8, ally: Allocator) !std.crypto.Certificate.rsa.PublicKey {
    _ = ally;
    if (proxy.len == 0) {
        return error.KeyProvider;
    }

    return std.crypto.Certificate.rsa.PublicKey{ .e = undefined, .n = undefined };
}
