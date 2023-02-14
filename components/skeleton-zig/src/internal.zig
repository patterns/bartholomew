const std = @import("std");
const was = @import("wasm.zig");
const handler = @import("handler.zig");


pub var RET_AREA: [28]u8 align(4) = std.mem.zeroes([28]u8);
// entry point from host
fn HttpHandler(
    arg_method: i32, arg0: i32,
    arg1: i32, arg2: i32,
    arg3: i32, arg4: i32,
    arg5: i32, arg_body: i32,
    arg_bodyAddr: i32, arg_bodyLen: i32,
    ) callconv(.C) i32 {
    _ = arg0;
    _ = arg1;
    _ = arg2;
    _ = arg3;
    _ = arg4;
    _ = arg5;

    var optbody: was.SpinHttpOptionBody = undefined;
    if (arg_body == 0) {
        optbody = was.SpinHttpOptionBody { .is_some = false, .val = undefined };
    } else {
        optbody = was.SpinHttpOptionBody {
            .is_some = true,
            .val = was.WasiMutSlice(u8).from_addr(arg_bodyAddr, arg_bodyLen),
        };
    }

    var request = was.SpinHttpRequest {
        .method = @intCast(was.HttpMethod, arg_method),
        .body = optbody,
    };

    var response = was.SpinHttpResponse {
        .status = @enumToInt(std.http.Status.not_found),
        .body = undefined,
    };

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(!gpa.deinit());
    //const gpal = gpa.allocator();

    handler.handle(&request, &response);
    //userDefinedHandler(&request, &response);

    // mem address of buffer shared to the C/host
    var ptr: was.WasiAddr = @intCast(was.WasiAddr, @ptrToInt(&RET_AREA));
    // copy HTTP status code into the shared buffer
    @intToPtr([*c]i16, @intCast(u32, ptr)).* = @intCast(i16, response.status);

    return ptr;
}

fn CanonicalAbiRealloc(
    arg_ptr: ?*anyopaque,
    arg_origsz: usize,
    arg_align: usize,
    arg_newsz: usize,
    ) callconv(.C) ?*anyopaque {

    var ptr = arg_ptr;
    _ = arg_origsz;

    if (arg_newsz == @intCast(usize, 0)) {
        return @intToPtr(?*anyopaque, arg_align);
    }

    //var ret: ?*anyopaque = realloc(ptr, new_size);
    //if (!(ret != null)) {
        ////abort();
    //    @panic("FAIL realloc, no recovery.");
    //}
    //return ret;
    return ptr;
}
fn CanonicalAbiFree(
    arg_ptr: ?*anyopaque,
    arg_size: usize,
    arg_align: usize,
    ) callconv(.C) void {

    var ptr = arg_ptr;
    var size = arg_size;
    var @"align" = arg_align;
    _ = @TypeOf(@"align");
    if (size == @bitCast(c_uint, @as(c_int, 0))) return;

    //TODO use the wasm heap allocator
    //free(ptr);
    _ = ptr;
}


