
const internal = @import("internal.zig");

pub fn main() void {
    @import("std").debug.print("workaround ::main error", .{});
}

comptime {
    @export(internal.HttpHandler,
        .{ .name = "handle-http-request", .linkage = .Strong });
    @export(internal.CanonicalAbiRealloc,
        .{ .name = "canonical_abi_realloc", .linkage = .Strong });
    @export(internal.CanonicalAbiFree,
        .{ .name = "canonical_abi_free", .linkage = .Strong });
}

