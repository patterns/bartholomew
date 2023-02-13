const std = @import("std");

//TODO provide "register" to parameterize the custom function
fn customSpinHelloWorld(req: *SpinHttpRequest, res: *SpinHttpResponse) void {
    _ = req.method;
    res.status = @enumToInt(std.http.Status.teapot);
}

pub var RET_AREA: [28]u8 align(4) = std.mem.zeroes([28]u8);

fn HttpHandler(
    arg: i32,
    arg0: i32,
    arg1: i32,
    arg2: i32,
    arg3: i32,
    arg4: i32,
    arg5: i32,
    arg6: i32,
    arg7: i32,
    arg8: i32,
) callconv(.C) i32 {
    _ = arg0;
    _ = arg1;
    _ = arg2;
    _ = arg3;
    _ = arg4;
    _ = arg5;

    var optbody: SpinHttpOptionBody = undefined;
    if (arg6 == 0) {
        optbody = SpinHttpOptionBody{ .is_some = false, .val = undefined };
    } else {
        optbody = SpinHttpOptionBody{
            .is_some = true,
            .val = WasiMutSlice(u8).from_addr(arg7, arg8),
        };
    }

    var request = SpinHttpRequest{
        .method = @bitCast(HttpMethod, @truncate(i8, arg)),
        .body = optbody,
    };

    var response = SpinHttpResponse{
        .status = @enumToInt(std.http.Status.not_found),
        .body = undefined,
    };

    customSpinHelloWorld(&request, &response);

    // mem address of buffer shared to the C/host
    var ptr: WasiAddr = @intCast(WasiAddr, @ptrToInt(&RET_AREA));
    // copy response status into the shared buffer
    @intToPtr([*c]i16, @bitCast(u32, ptr)).* = @bitCast(i16, response.status);

    return ptr;
}

fn CanonicalAbiRealloc(
    arg_ptr: ?*anyopaque,
    arg_orig_size: usize,
    arg_align: usize,
    arg_new_size: usize,
) callconv(.C) ?*anyopaque {
    var ptr = arg_ptr;
    var orig_size = arg_orig_size;
    _ = @TypeOf(orig_size);
    var @"align" = arg_align;
    var new_size = arg_new_size;
    if (new_size == @bitCast(c_uint, @as(c_int, 0))) {
        return @intToPtr(?*anyopaque, @"align");
    }
    //TODO use the wasm heap allocator
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

pub const WasiAddr = i32;
pub const Char8 = u8;
pub const Char32 = u32;
pub fn WasiMutPtr(comptime T: type) type {
    return [*c]T;
}
pub fn WasiMutSlice(comptime T: type) type {
    return extern struct {
        const This = @This();
        ptr: WasiMutPtr(T),
        len: usize,

        fn from_addr(addr: WasiAddr, len: i32) This {
            return This{
                .ptr = @intToPtr(WasiMutPtr(T), @bitCast(u32, addr)),
                .len = @bitCast(usize, len),
            };
        }

        fn from_slice(slice: []u8) This {
            return This{ .ptr = slice.ptr, .len = slice.len };
        }

        fn as_slice(wasi_slice: This) []u8 {
            return wasi_slice.ptr[wasi_slice.len];
        }
    };
}

/// HTTP status codes.
pub const HttpStatus = u16;
/// HTTP method verbs.
pub const HttpMethod = u8;

/// Memory location for the HTTP content body.
pub const BodyAddr = WasiAddr;

//pub const SpinHttpBody = extern struct {
//    ptr: WasiMutPtr(u8),
//    len: usize,
//};

pub const SpinHttpOptionBody = extern struct {
    is_some: bool,
    //val: SpinHttpBody,
    val: WasiMutSlice(u8),
};

// writer for consumer of the SDK
pub const SpinHttpResponse = extern struct {
    status: HttpStatus,
    //headers: spin_http_option_headers_t,
    body: SpinHttpOptionBody,
};

// reader for consumer of the SDK
pub const SpinHttpRequest = extern struct {
    method: HttpMethod,
    //uri: spin_http_uri_t,
    //headers: spin_http_headers_t,
    //params: spin_http_params_t,
    body: SpinHttpOptionBody,
};
