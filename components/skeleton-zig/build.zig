const std = @import("std");

pub fn build(b: *std.build.Builder) !void {
    b.setPreferredReleaseMode(std.builtin.Mode.ReleaseSafe);
    const ww = try std.zig.CrossTarget.parse(.{.arch_os_abi = "wasm32-wasi"});
    const target = b.standardTargetOptions(.{.default_target = ww});

    const lib = b.addStaticLibrary("spin", null);
    lib.setTarget(target);
    lib.linkLibC();
    lib.addIncludeDir("deps/spin/http");
    lib.addIncludeDir("deps/spin/redis");
    lib.addCSourceFiles(&.{
        "deps/spin/http/spin-http.c",
        "deps/spin/http/wasi-outbound-http.c",
        "deps/spin/redis/spin-redis.c",
        "deps/spin/redis/outbound-redis.c",
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
    exe.addIncludeDir("deps/spin/http");
    exe.addIncludeDir("deps/spin/redis");

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
