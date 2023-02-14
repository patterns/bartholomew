const std = @import("std");


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

