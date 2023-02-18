const std = @import("std");
const bld = std.build;
pub fn build(b: *bld.Builder) !void {
    const ww = try std.zig.CrossTarget.parse(.{.arch_os_abi = "wasm32-wasi"});
    const targ = b.standardTargetOptions(.{.default_target = ww});
    const mode = b.standardOptimizeOption(.{});
    const bopt = bld.ExecutableOptions {
        .name = "webcomponent",
        .root_source_file = bld.FileSource { .path = "src/main.zig"},
        .target = targ,
        .optimize = mode,
    };

    const exe = b.addExecutable(bopt);
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
