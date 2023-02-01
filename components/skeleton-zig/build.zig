const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    b.setPreferredReleaseMode(std.builtin.Mode.ReleaseSafe);
    const xt = try std.zig.CrossTarget.parse(.{.arch_os_abi = "wasm32-wasi"});
    const target = b.standardTargetOptions(.{.default_target = xt});

    const lib = b.addStaticLibrary("fermyon", null);
    lib.setTarget(target);
    lib.linkLibC();
    lib.addIncludeDir("deps/fermyon/http");
    lib.addIncludeDir("deps/fermyon/redis");
    lib.addCSourceFiles(&.{
        "deps/fermyon/http/spin-http.c",
        "deps/fermyon/http/wasi-outbound-http.c",
        "deps/fermyon/redis/spin-redis.c",
        "deps/fermyon/redis/outbound-redis.c",
    }, &.{
        "-Wall",
        "-Wno-unused-parameter",
        "-Wno-switch-bool",
    });


    const exe = b.addExecutable("webcomponent", "src/component.zig");
    exe.setTarget(target);
    exe.install();
    exe.linkLibC();
    exe.linkLibrary(lib);
    exe.addIncludeDir("deps/fermyon/http");
    exe.addIncludeDir("deps/fermyon/redis");

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
