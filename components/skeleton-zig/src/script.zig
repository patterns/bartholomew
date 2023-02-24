const std = @import("std");
const lib = @import("lib.zig");

// root/file struct
const Script = @This();

const Impl = struct { attached: bool, eval: lib.EvalFn };

var script_chain: [2]Impl = undefined;

pub const AttachOption = enum { vanilla, custom, both };

// attach/register scripts
pub fn init(config: anytype) void {
    script_chain[0] = Impl{ .attached = false, .eval = VanillaScriptImpl.eval };
    script_chain[1] = Impl{ .attached = false, .eval = CustomScriptImpl.eval };

    switch (config.attach) {
        .custom => script_chain[1].attached = true,
        .both => {
            script_chain[0].attached = true;
            script_chain[1].attached = true;
        },
        else => script_chain[0].attached = true,
    }
}

// express scripts which are attached
pub fn eval(w: *lib.HttpResponse, r: *lib.HttpRequest) void {
    for (script_chain) |script| {
        if (script.attached) {
            // mutates the response
            script.eval(w, r);
        }
    }
}

// custom script implementation
const CustomScriptImpl = struct {
    var attached = false;
    fn eval(w: *lib.HttpResponse, req: *lib.HttpRequest) void {
        if (req.method == 1) {
            w.status = @enumToInt(std.http.Status.locked);
        } else {
            w.status = @enumToInt(std.http.Status.method_not_allowed);
        }
    }
};

// skeleton/template implementation
const VanillaScriptImpl = struct {
    var attached = false;
    fn eval(w: *lib.HttpResponse, req: *lib.HttpRequest) void {
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
            w.status = @enumToInt(std.http.Status.teapot);
            w.headers.put("Content-Type", "application/json") catch {
                std.debug.print("ERROR response header", .{});
            };
            w.headers.put("X-Vanilla-Test", "lorem-ipsum") catch {
                std.debug.print("ERROR response header", .{});
            };
            w.body.appendSlice("{\"data\": \"vanilla-test\"}") catch {
                std.debug.print("ERROR response body", .{});
            };
        } else {
            w.status = @enumToInt(std.http.Status.method_not_allowed);
        }
    }
};
