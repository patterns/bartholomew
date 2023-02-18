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
pub fn eval(req: *was.SpinHttpRequest, res: *was.SpinHttpResponse) void {
    return Impl.eval(req, res);
}

// custom script implementation
const CustomScriptImpl = struct {
    fn eval(req: *was.SpinHttpRequest, res: *was.SpinHttpResponse) void {
        if (req.method == 1) {
            res.status = @enumToInt(std.http.Status.locked);
        } else {
            res.status = @enumToInt(std.http.Status.method_not_allowed);
        }
    }
};

// skeleton/template implementation
const VanillaScriptImpl = struct {
    fn eval(req: *was.SpinHttpRequest, res: *was.SpinHttpResponse) void {
        const sz = req.uri.len;
        const msg = req.uri.ptr[0..sz];
        std.debug.print("URI: {s}\n", .{msg});
        std.debug.print("headers count: {d}\n", .{req.headers.len});
        //for (req.headers) |hd| {
        //    std.debug.print("kv: {s}, {s}\n", .{ hd.f0.ptr.*, hd.f1.ptr.* });
        //}

        // POST is #1, GET is #0
        if (req.method == 1) {
            res.status = @enumToInt(std.http.Status.teapot);
        } else {
            res.status = @enumToInt(std.http.Status.method_not_allowed);
        }
    }
};
