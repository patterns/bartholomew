const std = @import("std");

const sdk = @cImport({
    @cInclude("stddef.h");
    @cInclude("spin-http.h");
});

const str = @import("strings.zig");
const store = @import("store.zig");
const status = @import("status.zig");

const Gpa = std.heap.GeneralPurposeAllocator(.{});

// Entry point required by the Spin host.
export fn spin_http_handle_http_request(req: *sdk.spin_http_request_t, res: *sdk.spin_http_response_t) callconv(.C) void {
    defer sdk.spin_http_request_free(req);

    // For an inbox endpoint, only allow POST requests.
    if (req.method != sdk.SPIN_HTTP_METHOD_POST) return status.nomethod(res);
    if (!req.body.is_some) return status.bad(res);

    var gpa = Gpa{};
    defer std.debug.assert(!gpa.deinit());
    const gpal = gpa.allocator();

    var check = str.pairs(gpal, req);
    defer check.deinit();
    // TODO free the k/v pairs
    // TODO verify signature
    const hdrsig = check.get("signature") orelse "";
    if (str.eq("", hdrsig)) return status.forbidden(res);

    const sz = req.body.val.len;
    // restrict max to 1MB
    if (sz > 1048576) return status.toolarge(res);

    var json_body = std.ArrayList(u8).init(gpal);
    defer json_body.deinit();
    json_body.appendSlice(req.body.val.ptr[0..sz]) catch return status.noaccept(res);
    const sane_json = std.json.validate(json_body.items);
    if (!sane_json) return status.unprocessable(res);

    var parser = std.json.Parser.init(gpal, false);
    defer parser.deinit();
    var tree = parser.parse(json_body.items) catch return status.expectation(res);
    defer tree.deinit();

    const activity_found = tree.root.Object.contains("type");
    if (!activity_found) return status.dependency(res);

    // JSON value for the (activity) "type" property must be of string.
    // TODO check this requirement (sanity check / guard)
    var json_val = tree.root.Object.get("type").?;
    const act = json_val.String;
    if (str.eq("Reject", act) or str.eq("Undo", act)) {
        store.enqueue(gpal, tree) catch return status.storage(res);
    } else if (str.eq("Accept", act)) {
        store.enqueue(gpal, tree) catch return status.storage(res);
    } else if (str.eq("Follow", act)) {
        store.enqueue(gpal, tree) catch return status.storage(res);
    } else {
        store.alarm(gpal, &json_body, check) catch return status.unavailable(res);
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

