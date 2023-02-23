const std = @import("std");
const was = @import("wasm.zig");

const Webfinger = @This();

const Impl = WebfingerImpl;

pub fn eval(w: *was.HttpResponse, r: *was.HttpRequest) void {
    Impl.eval(w, r);
}

const webfinger_json = @embedFile("webfinger.json");

const WebfingerImpl = struct {
    fn eval(w: *was.HttpResponse, req: *was.HttpRequest) void {
        if (req.method == 1) {
            w.status = @enumToInt(std.http.Status.method_not_allowed);
            return;
        }

        if (req.headers.get("spin-full-url")) |full| {
            const verify = unknownResource(full) catch false;
            if (!verify) {
                w.status = @enumToInt(std.http.Status.internal_server_error);
                return;
            }
        } else {
            w.status = @enumToInt(std.http.Status.internal_server_error);
            return;
        }

        w.headers.put("Content-Type", "application/jrd+json") catch {
            std.debug.print("ERROR response header", .{});
        };
        w.headers.put("Access-Control-Allow-Origin", "*") catch {
            std.debug.print("ERROR response header", .{});
        };
        w.body.appendSlice(webfinger_json) catch {
            std.debug.print("ERROR response body", .{});
            w.status = @enumToInt(std.http.Status.internal_server_error);
            return;
        };
        w.status = @enumToInt(std.http.Status.ok);
    }
};

fn unknownResource(full: []const u8) !bool {
    var check = try std.Uri.parse(full);
    std.debug.print("DEBUG uri parsed {s}\n", .{check.query.?});

    //TODO extract query param 'resource' then compare against know list

    return true;
}
