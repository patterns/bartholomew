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

pub fn expectation(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.expectation_failed);
}

pub fn dependency(res: *sdk.spin_http_response_t) void {
    code(res, std.http.Status.failed_dependency);
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

fn code(res: *sdk.spin_http_response_t, comptime sc: std.http.Status) void {
    res.status = @enumToInt(sc);
}
