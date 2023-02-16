const std = @import("std");
const builtin = @import("builtin");
const was = @import("wasm.zig");

// builder.zig sets release/optimize mode
const DEBUG = (builtin.mode == .Debug);

// file struct type
const Script = @This();

// simple toggle to demonstrate multiple implementations
const Impl = if (!DEBUG)
    CustomScriptImpl
else
    VanillaScriptImpl;

/// primary field that refers to the _active_ implementation
impl: Impl,

/// public/callable func member (that implementers are required to provide)
pub fn run(req: *was.SpinHttpRequest, res: *was.SpinHttpResponse) void {
    return Impl.run(req, res);
}

// a handler implementation
const CustomScriptImpl = struct {
    fn run(req: *was.SpinHttpRequest, res: *was.SpinHttpResponse) void {
        if (req.method == 1) {
            res.status = @enumToInt(std.http.Status.locked);
        } else {
            res.status = @enumToInt(std.http.Status.method_not_allowed);
        }
    }
};

// skeleton/template implementation
const VanillaScriptImpl = struct {
    fn run(req: *was.SpinHttpRequest, res: *was.SpinHttpResponse) void {
        // POST is #1, GET is #0
        if (req.method == 1) {
            res.status = @enumToInt(std.http.Status.teapot);
        } else {
            res.status = @enumToInt(std.http.Status.method_not_allowed);
        }
    }
};
