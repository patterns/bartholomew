const std = @import("std");
const sdk = @cImport({
    @cInclude("stddef.h");
    @cInclude("spin-http.h");
});

// Entry point required by the Spin host
export fn spin_http_handle_http_request(req: *sdk.spin_http_request_t, res: *sdk.spin_http_response_t) callconv(.C) void {
    defer sdk.spin_http_request_free(req);

    // TODO restrict path? (or just rely on routing)

    if (req.method != sdk.SPIN_HTTP_METHOD_POST) {
        res.status = @as(c_uint, 405);
        return;
    }

    // TODO Verify header for Signature and Content-Type

    const sz = req.body.val.len;
    if (req.body.is_some) {
        if (sz > 1048576) {
            // restrict max to 1MB
            res.status = @as(c_uint, 413);
            return;
        }

        const bodslc = req.body.val.ptr[0..sz];
        std.testing.expectEqual(bodslc.len, sz) catch {
            //TODO is this un/safe? (slicing c-ptr)
            res.status = @as(c_uint, 422);
            return;
        };

        const wellformed = std.json.validate(bodslc);
        if (!wellformed) {
            res.status = @as(c_uint, 406);
            return;
        }
    }

    // rehydrate json and dispatch by activity-type
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit());
    const allocator = gpa.allocator();
    var parser = std.json.Parser.init(allocator, false);
    var tree = parser.parse(req.body.val.ptr[0..sz]) catch {
        res.status = @as(c_uint, 417);
        return;
    };
    defer tree.deinit();
    const found = tree.root.Object.contains("type");
    if (!found) {
        res.status = @as(c_uint, 424);
        return;
    }
    var elem = tree.root.Object.get("type").?;
    switch (elem) {
        //"Reject", "Undo" => res.status = @as(c_uint, 418),
        //"Accept" => res.status = @as(c_uint, 418),
        //"Follow" => res.status = @as(c_uint, 418),
        .String => |val| {
            res.status = @as(c_uint, 207);
            //TODO publish to redis
            _ = val;
            return;
        },
        else => {res.status = @as(c_uint, 418); return;},
    }

    res.status = @as(c_uint, 200);
}



// Stub needed to suppress a "import env::main" error
pub fn main() void {
    std.debug.print("main function stub", .{});
}

