const std = @import("std");

const sdk = @cImport({
    @cInclude("stddef.h");
    @cInclude("spin-http.h");
});

pub fn nomethod(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.method_not_allowed);
}

pub fn bad(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.bad_request);
}

pub fn forbidden(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.forbidden);
}

pub fn toolarge(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.payload_too_large);
}

pub fn unprocessable(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.unprocessable_entity);
}

pub fn noaccept(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.not_acceptable);
}

pub fn precondition(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.precondition_required);
}

pub fn unavailable(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.service_unavailable);
}

pub fn storage(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.insufficient_storage);
}

pub fn nocontent(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.no_content);
}

pub fn ok(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.ok);
}

// DEBUG
pub fn tooearly(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.too_early);
}

fn code(res: *sdk.spin_http_response_t, comptime sc: std.http.Status) void {
    res.status = @enumToInt(sc);
}

// respond with JSON content
//pub fn json(al: std.mem.Allocator, res: *sdk.spin_http_response_t) void {
pub fn json(res: *sdk.spin_http_response_t) void {
    //const res = args.r;
    //res.status = @enumToInt(args.status);
    res.status = @enumToInt(std.http.Status.teapot);

    //if (args.data.len == 0) return;
    ////var js = try al.dupeZ(u8, args.data);
    //const js: [:0]u8 = try al.dupeZ(u8, "DEBUG hardcoded");
    //defer al.free(js);
    //res.body.val.ptr = js.ptr;
    //res.body.val.len = js.len;
    //res.body.is_some = true;
}
