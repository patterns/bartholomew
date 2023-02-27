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

        //TODO verify signature
        //     verify timestamp
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
        redis.enqueue(allocator, tree) catch {
            log.err("save failed", .{});
            return status.internal(w);
        };

        w.headers.put("Content-Type", "application/json") catch {
            log.err("response header, OutOfMem", .{});
        };

        status.ok(w);
    }
};

fn unknownSignature(allocator: Allocator, req: *lib.HttpRequest) bool {
    var bad = true;
    // 1. from the signature header, read the 'keyId'
    // 2. fetch the public key using the value in step#1
    // 3. from the signature header, read the 'headers'
    // 4. construct the input-string data using the value in step#3
    // 5. calculate the expected signature with the public key and input-string
    // 6. compare against the value in the signature header

    var base64 = signature.calculate(allocator, .{
        .public = true,
        .key = null,
        .request = req,
    }) catch {
        log.err("calculate failed", .{});
        return bad;
    };
    log.debug("calc public, {s}\n", .{base64});

    if (req.headers.get("signature")) |sig| {
        log.debug("signature hdr, {s}\n", .{sig});
    } else {
        log.err("header signature required\n", .{});
        return bad;
    }

    return false;
}
