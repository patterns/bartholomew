const std = @import("std");
const sp = @cImport({
    @cInclude("stddef.h");
    @cInclude("spin-http.h");
});

// To be invoked by Spin executor
export fn spin_http_handle_http_request(req: *sp.spin_http_request_t, res: *sp.spin_http_response_t) callconv(.C) void {
    defer sp.spin_http_request_free(req);

    if (req.method != sp.SPIN_HTTP_METHOD_GET) {
        res.status = @as(c_uint, 418);
        ////res.status = sp.SPIN_HTTP_HTTP_ERROR_REQUEST_ERROR;
        return;
    }


    // TODO
    res.status = @as(c_uint, 200);
    ////res.status = sp.SPIN_HTTP_HTTP_ERROR_SUCCESS;
}



pub fn main() void {
    std.debug.print("main function entry", .{});
}

