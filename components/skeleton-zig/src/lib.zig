const std = @import("std");
//const webfinger = @import("webfinger.zig");
//const actor = @import("actor.zig");
//const outbox = @import("outbox.zig");
const inbox = @import("inbox.zig");
const row = @import("rows.zig");
const Allocator = std.mem.Allocator;

//TODO think interface
pub const EvalFn = *const fn (a: Allocator, w: *HttpResponse, r: *SpinRequest) void;

// start exports to comply with host
var RET_AREA: [28]u8 align(4) = std.mem.zeroes([28]u8);
fn GuestHttpStart(
    arg_method: i32,
    arg_uriAddr: WasiAddr,
    arg_uriLen: i32,
    arg_hdrAddr: WasiAddr,
    arg_hdrLen: i32,
    arg_paramAddr: WasiAddr,
    arg_paramLen: i32,
    arg_body: i32,
    arg_bodyAddr: WasiAddr,
    arg_bodyLen: i32,
) callconv(.C) WasiAddr {
    //const allocator = std.heap.wasm_allocator;
    var arena = std.heap.ArenaAllocator.init(std.heap.wasm_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var request = SpinRequest.init(
        allocator,
        arg_method,
        arg_uriAddr,
        arg_uriLen,
        arg_hdrAddr,
        arg_hdrLen,
        arg_paramAddr,
        arg_paramLen,
        arg_body,
        arg_bodyAddr,
        arg_bodyLen,
    );
    defer request.deinit();
    var response = HttpResponse.init(allocator);
    defer response.deinit();

    //TODO use comptime to have compiler catch problems
    //script.init(.{.attach = script.AttachOption.vanilla});
    //script.eval(&response, &request);
    //webfinger.eval(allocator, &response, &request);
    //actor.eval(allocator, &response, &request);
    //outbox.eval(allocator, &response, &request);
    inbox.eval(allocator, &response, &request);

    // address of memory shared to the C/host
    var re: WasiAddr = @intCast(WasiAddr, @ptrToInt(&RET_AREA));
    // copy HTTP status code into the shared mem
    @intToPtr([*c]i16, @intCast(usize, re)).* = @intCast(i16, response.status);
    // copy headers to shared mem
    if (response.headers.count() != 0) {
        var ar = response.headers_as_array(allocator).items;
        @intToPtr([*c]i8, @intCast(usize, re + 4)).* = 1;
        @intToPtr([*c]i32, @intCast(usize, re + 12)).* = @bitCast(i32, ar.len);
        @intToPtr([*c]i32, @intCast(usize, re + 8)).* = @intCast(i32, @ptrToInt(ar.ptr));
    } else {
        @intToPtr([*c]i8, @intCast(usize, re + 4)).* = 0;
    }
    // copy body to shared mem
    if (response.body.items.len != 0) {
        var cp = allocator.dupe(u8, response.body.items) catch {
            @panic("FAIL response OutOfMem");
        };
        @intToPtr([*c]i8, @intCast(usize, re + 16)).* = 1;
        @intToPtr([*c]i32, @intCast(usize, re + 24)).* = @bitCast(i32, cp.len);
        @intToPtr([*c]i32, @intCast(usize, re + 20)).* = @intCast(i32, @ptrToInt(cp.ptr));
    } else {
        @intToPtr([*c]i8, @intCast(usize, re + 16)).* = 0;
    }

    return re;
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
            @panic("FAIL alloc OutOfMem");
        };
        return newslice.ptr;
    }

    var slice = @ptrCast([*]u8, arg_ptr.?)[0..arg_oldsz];
    var reslice = allocator.realloc(slice, arg_newsz) catch {
        @panic("FAIL realloc OutOfMem");
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

    const slice = @ptrCast([*]u8, arg_ptr.?)[0..arg_size];
    std.heap.wasm_allocator.free(slice);
}
// end exports to comply with host

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
    pub fn dupe(self: Self, allocator: Allocator) []u8 {
        const old = self.ptr[0..self.len];
        var cp = allocator.dupe(u8, old) catch {
            @panic("FAIL xdata dupe ");
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

// list conversion from C arrays
fn xlist(ally: Allocator, addr: WasiAddr, rowcount: i32) !row.SourceHeaders {
    var record = @intToPtr([*c]WasiTuple, @intCast(usize, addr));
    const max = @intCast(usize, rowcount);
    var list = row.SourceHeaders{};
    var rownum: usize = 0;
    while (rownum < max) : (rownum +%= 1) {
        var tup = record[rownum];
        const fld = try ally.dupeZ(u8, tup.f0.ptr[0..tup.f0.len]);
        const val = try ally.dupeZ(u8, tup.f1.ptr[0..tup.f1.len]);
        try list.append(ally, .{ .field = fld, .value = val });

        // free old kv
        CanonicalAbiFree(@ptrCast(?*anyopaque, tup.f0.ptr), tup.f0.len, 1);
        CanonicalAbiFree(@ptrCast(?*anyopaque, tup.f1.ptr), tup.f1.len, 1);
    }
    // free the old array
    CanonicalAbiFree(@ptrCast(?*anyopaque, record), max *% 16, 4);
    return list;
}

// map conversion from C arrays (leaning on xlist as primary to strive for minimal)
fn xmap(al: Allocator, addr: WasiAddr, len: i32) std.StringHashMap([]const u8) {
    var record = @intToPtr([*c]WasiTuple, @intCast(usize, addr));
    const count = @intCast(usize, len);

    var map = std.StringHashMap([]const u8).init(al);
    var i: usize = 0;
    while (i < count) : (i +%= 1) {
        var kv = record[i];

        var key = al.dupe(u8, kv.f0.ptr[0..kv.f0.len]) catch {
            @panic("FAIL map key dupe ");
        };
        var val = al.dupe(u8, kv.f1.ptr[0..kv.f1.len]) catch {
            @panic("FAIL map val dupe ");
        };

        map.put(key, val) catch {
            @panic("FAIL map put, ");
        };
        // free old kv
        CanonicalAbiFree(@ptrCast(?*anyopaque, kv.f0.ptr), kv.f0.len, 1);
        CanonicalAbiFree(@ptrCast(?*anyopaque, kv.f1.ptr), kv.f1.len, 1);
    }
    // free the old array
    CanonicalAbiFree(@ptrCast(?*anyopaque, record), count *% 16, 4);
    return map;
}

// writer for ziglang consumer
pub const HttpResponse = struct {
    const Self = @This();
    status: HttpStatus,
    headers: std.StringHashMap([]const u8),
    body: std.ArrayList(u8),

    pub fn init(allocator: Allocator) Self {
        return Self{
            .status = @enumToInt(std.http.Status.not_found),
            .headers = std.StringHashMap([]const u8).init(allocator),
            .body = std.ArrayList(u8).init(allocator),
        };
    }
    // conversion for C/interop
    pub fn headers_as_array(self: Self, allocator: Allocator) std.ArrayList(WasiTuple) {
        var arr = std.ArrayList(WasiTuple).init(allocator);
        var iter = self.headers.iterator();
        while (iter.next()) |entry| {
            var key = allocator.dupe(u8, entry.key_ptr.*) catch {
                @panic("FAIL headers key dupe");
            };
            var val = allocator.dupe(u8, entry.value_ptr.*) catch {
                @panic("FAIL headers val dupe");
            };
            var tup = WasiTuple{
                .f0 = WasiStr{ .ptr = key.ptr, .len = key.len },
                .f1 = WasiStr{ .ptr = val.ptr, .len = val.len },
            };
            arr.append(tup) catch {
                @panic("FAIL headers slice");
            };
        }
        return arr;
    }
    pub fn deinit(self: *Self) void {
        //TODO free map items
        self.headers.deinit();
        self.body.deinit();
    }
};

// reader for ziglang consumer
pub const SpinRequest = struct {
    const Self = @This();
    ally: Allocator,
    method: HttpMethod,
    uri: []const u8,
    headers: row.SourceHeaders,
    params: row.SourceHeaders,
    body: std.ArrayList(u8),

    // instantiate from C/interop (using addresses)
    pub fn init(
        ally: Allocator,
        method: i32,
        uriAddr: WasiAddr,
        uriLen: i32,
        hdrAddr: WasiAddr,
        hdrLen: i32,
        paramAddr: WasiAddr,
        paramLen: i32,
        bodyEnable: i32,
        bodyAddr: WasiAddr,
        bodyLen: i32,
    ) Self {
        var curi = xdata.init(uriAddr, uriLen);
        var uri = curi.dupe(ally);
        curi.deinit();

        var body = std.ArrayList(u8).init(ally);
        if (bodyEnable == 1) {
            var cbod = xdata.init(bodyAddr, bodyLen);
            body.appendSlice(cbod.ptr[0..cbod.len]) catch {
                @panic("FAIL copying body from C addr");
            };
            cbod.deinit();
        }

        var headers = xlist(ally, hdrAddr, hdrLen) catch {
            @panic("FAIL copying headers from C addr");
        };
        var params = xlist(ally, paramAddr, paramLen) catch {
            @panic("FAIL copying params from C addr");
        };

        return Self{
            .ally = ally,
            .method = @intCast(HttpMethod, method),
            .uri = uri,
            .headers = headers,
            .params = params,
            .body = body,
        };
    }
    pub fn deinit(self: *Self) void {
        if (self.uri.len != 0) self.ally.free(self.uri);
        self.body.deinit();
        self.headers.deinit(self.ally);
        self.params.deinit(self.ally);
    }
};

// C/interop address
const WasiAddr = i32;
// "anon" struct just for address to tuple C/interop
const WasiStr = extern struct { ptr: [*c]u8, len: usize };
const WasiTuple = extern struct { f0: WasiStr, f1: WasiStr };

/// HTTP status codes.
pub const HttpStatus = u16;
/// HTTP method verbs.
pub const HttpMethod = u8;
