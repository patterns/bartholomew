const std = @import("std");

pub fn selfActor() ?[]u8 {
    return get("self_actor");
}
pub fn siteSubdomain() ?[]u8 {
    return get("site_subdomain");
}
pub fn redisAddress() ?[]u8 {
    return get("redis_address");
}
pub fn httpsigProxy() ?[]u8 {
    return get("httpsig_proxy");
}

/////////////////////////////////////////////////////////////
// WASI C/interop

// (see https://github.com/ziglang/zig/issues/2274)
pub extern "spin-config" fn @"get-config"(i32, i32, i32) void;

var RET_AREA: [16]u8 align(4) = std.mem.zeroes([16]u8);

// retrieve from the component manifest
pub fn get(key: []const u8) ?[]u8 {
    var setting: []u8 = undefined;
    var address: i32 = @intCast(i32, @ptrToInt(&RET_AREA));

    // ask the host
    @"get-config"(
        @intCast(i32, @ptrToInt(key.ptr)),
        @intCast(i32, key.len),
        address,
    );

    const errcode_ptr = @intToPtr([*c]u8, @intCast(usize, address));
    const errcode_val = @intCast(u32, errcode_ptr.*);
    if (errcode_val == 0) {
        // zero means ok
        const start_ptr = @intToPtr([*c]i32, @intCast(usize, address + 4));
        const start_val = start_ptr.*;
        const field_ptr = @intToPtr([*c]u8, @intCast(usize, start_val));
        const len_ptr = @intToPtr([*c]i32, @intCast(usize, address + 8));
        const len_val = @bitCast(usize, len_ptr.*);
        setting = field_ptr[0..len_val];
        // TODO dupe, and deallocate old data
        // (except, if multiple random lookups, need local cache)
    } else {
        // one means error
        std.log.err(" conf get: (more detail todo)\n", .{});
        // TODO null until we expand the detail hydration
        return null;
    }

    return setting;
}
