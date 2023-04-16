const std = @import("std");
const lib = @import("lib.zig");
const str = @import("strings.zig");
const status = @import("status.zig");
const config = @import("config.zig");
const redis = @import("redis.zig");
const signature = @import("signature.zig");
// TODO organize imports
const ro = @import("rows.zig");
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

fn unknownSignature(allocator: Allocator, req: lib.SpinRequest) !bool {
    const bad = true;

    var placeholder: ro.RawHeaders = undefined;
    var wrap = ro.HeaderList.init(allocator, placeholder);

    try signature.init(allocator, placeholder);

    var hashed = try signature.sha256Base(req, wrap);
    signature.attachFetch(MockKey);

    const check = signature.verify(allocator, hashed);
    log.debug("verify, {any}", .{check});

    // checks passed
    return !bad;
}

// need test cases for the httpsig input sequence
fn MockKey(allocator: Allocator, proxy: []const u8) signature.PublicKey {
    _ = allocator;
    log.debug("mock fetch, {s}\n", .{proxy});
    const key = signature.PublicKey{
        .N = std.mem.zeroes([]const u8),
        .E = std.mem.zeroes([]const u8),
    };
    return key;
}
