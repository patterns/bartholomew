const std = @import("std");
const script = @import("script.zig");

var RET_AREA: [28]u8 align(4) = std.mem.zeroes([28]u8);
fn GuestHttpStart(
    arg_method: i32,
    arg0: i32,
    arg1: i32,
    arg2: i32,
    arg3: i32,
    arg4: i32,
    arg5: i32,
    arg_body: i32,
    arg_bodyAddr: i32,
    arg_bodyLen: i32,
) callconv(.C) i32 {
    _ = arg0;
    _ = arg1;
    _ = arg2;
    _ = arg3;
    _ = arg4;
    _ = arg5;

    var optbody: SpinHttpOptionBody = undefined;
    if (arg_body == 0) {
        optbody = SpinHttpOptionBody{ .is_some = false, .val = undefined };
    } else {
        optbody = SpinHttpOptionBody{
            .is_some = true,
            .val = WasiMutSlice(u8).from_addr(arg_bodyAddr, arg_bodyLen),
        };
    }

    var request = SpinHttpRequest{
        .method = @intCast(HttpMethod, arg_method),
        .body = optbody,
    };

    var response = SpinHttpResponse{
        .status = @enumToInt(std.http.Status.not_found),
        .body = undefined,
    };

    script.run(&request, &response);

    // mem address of buffer shared to the C/host
    var ptr: WasiAddr = @intCast(WasiAddr, @ptrToInt(&RET_AREA));
    // copy HTTP status code into the shared buffer
    @intToPtr([*c]i16, @intCast(u32, ptr)).* = @intCast(i16, response.status);

    return ptr;
}
fn CanonicalAbiRealloc(
    arg_ptr: ?*anyopaque,
    arg_oldsz: usize,
    arg_align: usize,
    arg_newsz: usize,
) callconv(.C) ?*anyopaque {
    // null means *allocate memory*
    if (arg_ptr == null) {
        return @intToPtr(*anyopaque, arg_align);
    }
    const zslice = @ptrCast([*]u8, arg_ptr.?)[0..arg_oldsz];
    const allocator = std.heap.wasm_allocator;
    // realloc will take care when the specified size is zero
    const loc = allocator.realloc(zslice, arg_newsz) catch {
        std.debug.panic("FAIL realloc, oom", .{});
    };
    return loc.ptr;
}
fn CanonicalAbiFree(
    arg_ptr: ?*anyopaque,
    arg_size: usize,
    arg_align: usize,
) callconv(.C) void {
    _ = arg_align;
    if (arg_size == @intCast(usize, 0)) return;
    if (arg_ptr == null) return;

    const zslice = @ptrCast([*]u8, arg_ptr.?)[0..arg_size];
    const allocator = std.heap.wasm_allocator;
    allocator.free(zslice);
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

        pub fn from_addr(addr: WasiAddr, len: i32) This {
            return This{
                .ptr = @intToPtr(WasiMutPtr(T), @intCast(u32, addr)),
                .len = @intCast(usize, len),
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
