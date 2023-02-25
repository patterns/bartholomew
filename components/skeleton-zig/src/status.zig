const std = @import("std");
const lib = @import("lib.zig");

pub fn nomethod(w: *lib.HttpResponse) void {
    code(w, std.http.Status.method_not_allowed);
}

pub fn bad(w: *lib.HttpResponse) void {
    code(w, std.http.Status.bad_request);
}

pub fn internal(w: *lib.HttpResponse) void {
    code(w, std.http.Status.internal_server_error);
}

pub fn notfound(w: *lib.HttpResponse) void {
    code(w, std.http.Status.not_found);
}

pub fn forbidden(w: *lib.HttpResponse) void {
    code(w, std.http.Status.forbidden);
}

pub fn toolarge(w: *lib.HttpResponse) void {
    code(w, std.http.Status.payload_too_large);
}

pub fn unprocessable(w: *lib.HttpResponse) void {
    code(w, std.http.Status.unprocessable_entity);
}

pub fn noaccept(w: *lib.HttpResponse) void {
    code(w, std.http.Status.not_acceptable);
}

pub fn expectation(w: *lib.HttpResponse) void {
    code(w, std.http.Status.expectation_failed);
}

pub fn dependency(w: *lib.HttpResponse) void {
    code(w, std.http.Status.failed_dependency);
}

pub fn unavailable(w: *lib.HttpResponse) void {
    code(w, std.http.Status.service_unavailable);
}

pub fn storage(w: *lib.HttpResponse) void {
    code(w, std.http.Status.insufficient_storage);
}

pub fn nocontent(w: *lib.HttpResponse) void {
    code(w, std.http.Status.no_content);
}

pub fn ok(w: *lib.HttpResponse) void {
    code(w, std.http.Status.ok);
}

fn code(w: *lib.HttpResponse, comptime sc: std.http.Status) void {
    w.status = @enumToInt(sc);
}
