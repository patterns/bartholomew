const std = @import("std");
const print = @import("std").debug.print;
const sdk = @cImport({
    @cInclude("stddef.h");
    @cInclude("spin-http.h");
});

// Entry point required by the Spin host
export fn spin_http_handle_http_request(
        req: *sdk.spin_http_request_t,
        res: *sdk.spin_http_response_t) callconv(.C) void {

    defer sdk.spin_http_request_free(req);

    // TODO restrict path? (or just rely on routing)

    if (req.method != sdk.SPIN_HTTP_METHOD_POST) return httperr(res, 405);

    // TODO Verify header for Signature and Content-Type

    var g = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(!g.deinit());
    const al = g.allocator();

    var payload = std.ArrayList(u8).init(al);
    defer payload.deinit();

    if (req.body.is_some) {
        const sz = req.body.val.len;
        // restrict max to 1MB
        if (sz > 1048576) return httperr(res, 413);

        payload.appendSlice(req.body.val.ptr[0..sz]) catch return httperr(res, 506);
        const sane_json = std.json.validate(payload.items);
        if (!sane_json) return httperr(res, 406);
    }

    var parser = std.json.Parser.init(al, false);
    defer parser.deinit();
    var tree = parser.parse(payload.items) catch return httperr(res, 417);
    defer tree.deinit();

    const activity_found = tree.root.Object.contains("type");
    if (!activity_found) {
        return httperr(res, 424);
    }
    // TODO can we use the Value's stringify function ?
    var elem = tree.root.Object.get("type").?;
    const act = elem.String;
    if (streq("Reject", act) or streq("Undo", act)) {
        return httperr(res, 418);

    } else if (streq("Accept", act)) {
        return httperr(res, 207);

    } else if (streq("Follow", act)) {
        return httperr(res, 207);

    } else {
        return httperr(res, 418);
    }

    res.status = @as(c_uint, 200);
}

// Stub needed to suppress a "import env::main" error
pub fn main() void {
    print("main function stub", .{});
}

fn streq(comptime s1: []const u8, s2: []const u8) bool {
    return std.mem.eql(u8, s1, s2);
}

fn httperr(res: *sdk.spin_http_response_t, comptime stat: i32) void {
    // readable?
    res.status = @as(c_uint, stat);
}

