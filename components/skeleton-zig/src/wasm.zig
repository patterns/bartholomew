const std = @import("std");
const script = @import("script.zig");
const Allocator = std.mem.Allocator;

// start exports
var RET_AREA: [28]u8 align(4) = std.mem.zeroes([28]u8);
fn GuestHttpStart(
    arg_method: i32,
    arg_uriAddr: WasiAddr,
    arg_uriLen: i32,
    arg_hdrAddr: WasiAddr,
    arg_hdrLen: i32,
    arg_prmAddr: WasiAddr,
    arg_prmLen: i32,
    arg_body: i32,
    arg_bodyAddr: WasiAddr,
    arg_bodyLen: i32,
) callconv(.C) WasiAddr {
    const allocator = std.heap.wasm_allocator;
    // start request init
    var curi = xdata.init(arg_uriAddr, arg_uriLen);
    var uri = curi.dupe(allocator);
    curi.deinit();
    var body = std.ArrayList(u8).init(allocator);
    if (arg_body == 1) {
        var cbod = xdata.init(arg_bodyAddr, arg_bodyLen);
        body.appendSlice(cbod.ptr[0..cbod.len]) catch {
            std.debug.panic("FAIL body appendSlice", .{});
        };
        cbod.deinit();
    }
    var headers = xmap(allocator, arg_hdrAddr, arg_hdrLen);
    var params = xmap(allocator, arg_prmAddr, arg_prmLen);
    var request = SpinHttpRequest.init(
        allocator,
        @intCast(HttpMethod, arg_method),
        uri,
        headers,
        params,
        body,
    );
    // end request init
    defer request.deinit();

    var response = SpinHttpResponse{
        .status = @enumToInt(std.http.Status.not_found),
        //.body = undefined,
    };

    script.eval(&request, &response);

    // mem address of buffer shared to the C/host
    var addr: WasiAddr = @intCast(WasiAddr, @ptrToInt(&RET_AREA));
    // copy HTTP status code into the shared buffer
    @intToPtr([*c]i16, @intCast(usize, addr)).* = @intCast(i16, response.status);

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

    var slice = @ptrCast([*]u8, arg_ptr.?)[0..arg_oldsz];
    var reslice = allocator.realloc(slice, arg_newsz) catch {
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
    std.heap.wasm_allocator.free(zslice);
}
//end exports

// The basic type according to translate-c
// ([*c]u8 is both char* and uint8*)
const xdata = struct {
    const Self = @This();
    ptr: [*c]u8,
    len: usize,

    // cast address to pointer w/o allocation
    pub fn init(addr: WasiAddr, len: i32) Self {
        return Self{
            .ptr = @intToPtr([*c]u8, @intCast(usize, addr)),
            .len = @intCast(usize, len),
        };
    }
    // convert as slice w/ new memory (todo provide different return types explicitly i.e., dupeZ for the sentinel)
    pub fn dupe(self: Self, al: Allocator) []u8 {
        const old = self.ptr[0..self.len];
        var cp = al.dupe(u8, old) catch {
            std.debug.panic("FAIL xdata dupe ()", .{});
        };
        return cp;
    }
    // release memory that was allocated by CanonicalAbiAlloc
    pub fn deinit(self: *Self) void {
        CanonicalAbiFree(self.ptr, self.len, 1);
        self.len = 0;
        self.ptr = null;
    }
};

fn xmap(al: Allocator, addr: WasiAddr, len: i32) std.StringHashMap([]const u8) {
    const cstr = extern struct { ptr: [*c]u8, len: usize };
    const crow = extern struct { f0: cstr, f1: cstr };
    var rows = @intToPtr([*c]crow, @intCast(usize, addr));
    const count = @intCast(usize, len);

    var map = std.StringHashMap([]const u8).init(al);
    var i: usize = 0;
    while (i < count) : (i +%= 1) {
        var kv = rows[i];

        var key = al.dupe(u8, kv.f0.ptr[0..kv.f0.len]) catch {
            std.debug.panic("FAIL map key dupe ", .{});
        };
        var val = al.dupe(u8, kv.f1.ptr[0..kv.f1.len]) catch {
            std.debug.panic("FAIL map val dupe ", .{});
        };

        map.put(key, val) catch {
            std.debug.panic("FAIL hashmap put, {s}", .{key});
        };
        // free old kv
        CanonicalAbiFree(@ptrCast(?*anyopaque, kv.f0.ptr), kv.f0.len, 1);
        CanonicalAbiFree(@ptrCast(?*anyopaque, kv.f1.ptr), kv.f1.len, 1);
    }
    // free the old list
    CanonicalAbiFree(@ptrCast(?*anyopaque, rows), count *% 16, 4);
    return map;
}

// writer for ziglang consumer
pub const SpinHttpResponse = struct {
    status: HttpStatus,
    //headers: spin_http_option_headers_t,
    //body: SpinHttpOptionBody,
};

// reader for ziglang consumer
pub const SpinHttpRequest = struct {
    const Self = @This();
    allocator: Allocator,
    method: HttpMethod,
    uri: []const u8,
    headers: std.StringHashMap([]const u8),
    params: std.StringHashMap([]const u8),
    body: std.ArrayList(u8),

    pub fn init(
        a: Allocator,
        m: HttpMethod,
        u: []u8,
        h: std.StringHashMap([]const u8),
        p: std.StringHashMap([]const u8),
        b: std.ArrayList(u8),
    ) Self {
        return Self{
            .allocator = a,
            .method = m,
            .uri = u,
            .headers = h,
            .params = p,
            .body = b,
        };
    }
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.uri);
        self.body.deinit();
        self.headers.deinit();
        self.params.deinit();
    }
};

// see jedisct1/zigly
pub const WasiAddr = i32;
/// HTTP status codes.
pub const HttpStatus = u16;
/// HTTP method verbs.
pub const HttpMethod = u8;
