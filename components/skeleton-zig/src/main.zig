const std = @import("std");

const sdk = @import("wasm.zig");

pub fn main() void {
    std.debug.print("main function stub", .{});
}

comptime {
    @export(sdk.HttpHandler, .{ .name = "handle-http-request", .linkage = .Strong });
    @export(sdk.CanonicalAbiRealloc, .{ .name = "canonical_abi_realloc", .linkage = .Strong });
    @export(sdk.CanonicalAbiFree, .{ .name = "canonical_abi_free", .linkage = .Strong });
}
