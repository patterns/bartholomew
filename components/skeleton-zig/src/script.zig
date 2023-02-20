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
        std.debug.print("URI: {s}\n", .{req.uri});
        std.debug.print("headers: {d}\n", .{req.headers.count()});
        var it = req.headers.iterator();
        while (it.next()) |entry| {
            std.debug.print(": {s}, {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }
        std.debug.print("params: {d}\n", .{req.params.count()});
        var itp = req.params.iterator();
        while (itp.next()) |entry| {
            std.debug.print(": {s}, {s}\n", .{ entry.key_ptr.*, entry.value_ptr.* });
        }

        // POST is #1, GET is #0
        if (req.method == 1) {
            res.status = @enumToInt(std.http.Status.teapot);
        } else {
            res.status = @enumToInt(std.http.Status.method_not_allowed);
        }
    }
};
