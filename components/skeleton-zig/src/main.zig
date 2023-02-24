const lib = @import("lib.zig");

pub fn main() void {
    @import("std").debug.print("DEBUG placeholder ", .{});
}

comptime {
    @export(lib.GuestHttpStart, .{ .name = "handle-http-request", .linkage = .Strong });
    @export(lib.CanonicalAbiRealloc, .{ .name = "canonical_abi_realloc", .linkage = .Strong });
    @export(lib.CanonicalAbiFree, .{ .name = "canonical_abi_free", .linkage = .Strong });
}
