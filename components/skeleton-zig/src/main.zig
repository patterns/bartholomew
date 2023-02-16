const was = @import("wasm.zig");

pub fn main() void {
    @import("std").debug.print("workaround ::main error", .{});
}

comptime {
    @export(was.GuestHttpStart, .{ .name = "handle-http-request", .linkage = .Strong });
    @export(was.CanonicalAbiRealloc, .{ .name = "canonical_abi_realloc", .linkage = .Strong });
    @export(was.CanonicalAbiFree, .{ .name = "canonical_abi_free", .linkage = .Strong });
}
