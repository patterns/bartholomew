const std = @import("std");
const script = @import("script.zig");

var RET_AREA: [28]u8 align(4) = std.mem.zeroes([28]u8);
fn GuestHttpStart(
    arg_method: i32,
    arg_uriAddr: i32,
    arg_uriLen: i32,
    arg_hdrAddr: i32,
    arg_hdrLen: i32,
    arg4: i32,
    arg5: i32,
    arg_body: i32,
    arg_bodyAddr: i32,
    arg_bodyLen: i32,
) callconv(.C) i32 {
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
    const allocator = std.heap.wasm_allocator;
    const tmp = shadow.from_addr(allocator, arg_uriAddr, arg_uriLen);

    var request = SpinHttpRequest{
        .method = @intCast(HttpMethod, arg_method),
        .uri = tmp.as_string(),
        .headers = WasiMutSlice(SpinHttpTuple).from_addr(arg_hdrAddr, arg_hdrLen),
        .body = optbody,
    };

    var response = SpinHttpResponse{
        .status = @enumToInt(std.http.Status.not_found),
        .body = undefined,
    };

    script.eval(&request, &response);

    // mem address of buffer shared to the C/host
    var addr: WasiAddr = @intCast(WasiAddr, @ptrToInt(&RET_AREA));
    // copy HTTP status code into the shared buffer
    @intToPtr([*c]i16, @intCast(u32, addr)).* = @intCast(i16, response.status);

    return addr;
}
fn CanonicalAbiRealloc(
    arg_ptr: ?*anyopaque,
    arg_oldsz: usize,
    arg_align: usize,
    arg_newsz: usize,
) callconv(.C) ?*anyopaque {
    // zero means to _free_ in ziglang
    // TODO (need to confirm behavior from wit-bindgen version)
    if (arg_newsz == @intCast(usize, 0)) {
        return @intToPtr(?*anyopaque, arg_align);
    }

    const allocator = std.heap.wasm_allocator;
    // null means to _allocate_
    if (arg_ptr == null) {
        var newslice = allocator.alloc(u8, arg_newsz) catch {
            std.debug.panic("FAIL alloc, oom", .{});
        };
        return newslice.ptr;
    }

    var zslice = @ptrCast([*]u8, arg_ptr.?)[0..arg_oldsz];
    var reslice = allocator.realloc(zslice, arg_newsz) catch {
        std.debug.panic("FAIL realloc, oom", .{});
    };
    return reslice.ptr;
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

// convenience to learn different string conversions
const shadow = struct {
    const Self = @This();
    buffer: std.ArrayList(u8),

    pub fn from_literal(al: std.mem.Allocator, str: []const u8) Self {
        var sh = Self{ .buffer = std.ArrayList(u8).init(al) };
        sh.buffer.appendSlice(str);
        return sh;
    }
    pub fn from_addr(al: std.mem.Allocator, addr: WasiAddr, len: i32) Self {
        var sh = Self{ .buffer = std.ArrayList(u8).init(al) };
        const sz = @intCast(usize, len);
        const tmp = @intToPtr([*c]u8, @intCast(usize, addr));
        sh.buffer.appendSlice(tmp[0..sz]) catch {
            std.debug.panic("FAIL shadow, oom", .{});
        };
        return sh;
    }
    pub fn as_string(self: Self) WasiString {
        // coerce to [*c]const u8 (for interop)
        //var str: [*c]const u8 = self.items.ptr;
        const tmp = self.as_slice();
        return WasiString{
            .ptr = tmp.ptr,
            .len = tmp.len,
        };
    }
    pub fn deinit(self: Self) void {
        self.buffer.deinit();
    }

    fn as_slice(self: Self) []u8 {
        return self.buffer.items;
    }
};

// see jedisct1/zigly
pub const WasiAddr = i32;
pub const Char8 = u8;
pub const Char32 = u32;
pub const WasiString = extern struct {
    ptr: [*c]const u8,
    len: usize,
};
pub fn WasiMutPtr(comptime T: type) type {
    return [*c]T;
}
pub fn WasiMutSlice(comptime T: type) type {
    return extern struct {
        const Self = @This();
        ptr: WasiMutPtr(T),
        len: usize,
        //TODO deinit() to free mem?
        pub fn from_addr(addr: WasiAddr, len: i32) Self {
            return Self{
                .ptr = @intToPtr(WasiMutPtr(T), @intCast(usize, addr)),
                .len = @intCast(usize, len),
            };
        }
        pub fn as_string(wasi_slice: Self) []const u8 {
            const tmp: []const u8 = wasi_slice.as_slice();
            return tmp;
        }
        fn as_slice(wasi_slice: Self) []u8 {
            return wasi_slice.ptr[0..wasi_slice.len];
        }
    };
}

/// HTTP status codes.
pub const HttpStatus = u16;
/// HTTP method verbs.
pub const HttpMethod = u8;

/// Memory location for the HTTP content body.
pub const BodyAddr = WasiAddr;

pub const SpinHttpOptionBody = extern struct {
    is_some: bool,
    val: WasiMutSlice(u8),
};
pub const SpinHttpTuple = extern struct {
    f0: WasiString,
    f1: WasiString,
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
    uri: WasiString,
    headers: WasiMutSlice(SpinHttpTuple),
    //params: spin_http_params_t,
    body: SpinHttpOptionBody,
};
