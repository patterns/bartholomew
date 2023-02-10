const std = @import("std");
const sdk = @cImport({
    @cInclude("stddef.h");
    @cInclude("spin-http.h");
});
const str = @import("strings.zig");
const store = @import("store.zig");
const status = @import("status.zig");
const sign = @import("signature.zig");
const Gpa = std.heap.GeneralPurposeAllocator(.{});

// Entry point required by the Spin host.
pub export fn spin_http_handle_http_request(
    req: *sdk.spin_http_request_t,
    res: *sdk.spin_http_response_t,
) callconv(.C) void {
    defer sdk.spin_http_request_free(req);

    // For an inbox endpoint, only allow POST requests.
    if (req.method != sdk.SPIN_HTTP_METHOD_POST) return status.nomethod(res);
    if (!req.body.is_some) return status.bad(res);

    var gpa = Gpa{};
    defer std.debug.assert(!gpa.deinit());
    const gpal = gpa.allocator();

    var headers = str.pairs(gpal, req);
    defer headers.deinit();
    // TODO free the k/v pairs
    //DEBUG
    const sig_check = sign.verify(gpal, headers);
    if (!str.eq("SIGN.FAIL", sig_check)) {
        return status.json(res);
    } else {
        return status.forbidden(res);
    }

    const sz = req.body.val.len;
    // restrict max to 1MB
    if (sz > 1048576) return status.toolarge(res);

    var json_raw = std.ArrayList(u8).init(gpal);
    defer json_raw.deinit();
    json_raw.appendSlice(req.body.val.ptr[0..sz]) catch return status.noaccept(res);
    var tree = str.toTree(gpal, json_raw) catch return status.unprocessable(res);
    defer tree.deinit();

    const activity_found = tree.root.Object.contains("type");
    if (!activity_found) return status.precondition(res);

    // JSON value for the (activity) "type" property must be of string.
    var json_val = tree.root.Object.get("type").?;
    const act = json_val.String;
    if (str.eq("Reject", act) or str.eq("Undo", act)) {
        store.enqueue(gpal, tree) catch return status.storage(res);
    } else if (str.eq("Accept", act)) {
        store.enqueue(gpal, tree) catch return status.storage(res);
    } else if (str.eq("Follow", act)) {
        store.enqueue(gpal, tree) catch return status.storage(res);
    } else {
        store.alarm(gpal, &json_raw, headers) catch return status.unavailable(res);
        return status.nocontent(res);
    }

    status.ok(res);
}

// Stub needed to suppress a "import env::main" error.
pub fn main() void {
    std.debug.print("main function stub", .{});
}

//const ConfigError = error{RedisAddress};
//const LimitError = error{BufferSize};

