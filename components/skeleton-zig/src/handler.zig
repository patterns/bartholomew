const std = @import("std");
const builtin = @import("builtin");
const was = @import("wasm.zig");

// simple toggle to demonstrate multiple handler options
const DEBUG = (builtin.mode == .Debug);

const Handler = @This();
const Impl = if (!DEBUG)
    DefaultHandlerImpl
else
    ExampleHandlerImpl;


impl: Impl,

pub fn handle(req: *was.SpinHttpRequest, res: *was.SpinHttpResponse) void {
    return Impl.handle(req, res);
}

const DefaultHandlerImpl = struct {
    fn handle(req: *was.SpinHttpRequest, res: *was.SpinHttpResponse) void {
        if (req.method == 1) {
            res.status = @enumToInt(std.http.Status.locked);
        } else {
            res.status = @enumToInt(std.http.Status.method_not_allowed);
        }
    }
};

// skeleton/template as example implementation
const ExampleHandlerImpl = struct {
    fn handle(req: *was.SpinHttpRequest, res: *was.SpinHttpResponse) void {
        // POST is #1, GET is #0
        if (req.method == 1) {
            res.status = @enumToInt(std.http.Status.teapot);
        } else {
            res.status = @enumToInt(std.http.Status.method_not_allowed);
        }
    }
};


