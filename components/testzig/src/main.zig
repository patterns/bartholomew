const std = @import("std");
const sp = @cImport({
    @cInclude("stddef.h");
    @cInclude("spin-http.h");
});

export fn handleHttpRequest(req: *sp.spin_http_request_t, res: *sp.spin_http_response_t) void {
    _ = req.method;
    _ = @as(c_uint, res.status);

}

pub fn main() anyerror!void {
    std.log.info("All your codebase are belong to us.", .{});
}

test "basic test" {
    try std.testing.expectEqual(10, 3 + 7);
}


