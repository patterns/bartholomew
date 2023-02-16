const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    const ww = try std.zig.CrossTarget.parse(.{.arch_os_abi = "wasm32-wasi"});
    const target = b.standardTargetOptions(.{.default_target = ww});
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("webcomponent", "src/main.zig");
    exe.setBuildMode(mode);
    exe.setTarget(target);
    exe.install();
    exe.single_threaded = true;

    // export symbols (required in 0.11 see zig/issues/14139)
    const export_names = [_][]const u8 {
        "canonical_abi_free",
        "canonical_abi_realloc",
        "handle-http-request",
    };
    exe.export_symbol_names = &export_names;

}
