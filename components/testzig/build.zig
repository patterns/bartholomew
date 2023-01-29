const std = @import("std");

pub fn build(b: *std.build.Builder) void {
    const target = b.standardTargetOptions(.{});
    const mode = b.standardReleaseOptions();

    const lib = b.addStaticLibrary("learn-spin", null);
    lib.setTarget(target);
    lib.setBuildMode(mode);
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

    const exe = b.addExecutable("hello", "src/main.zig");
    exe.setTarget(target);
    exe.setBuildMode(mode);
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

    const exe_tests = b.addTest("src/main.zig");
    exe_tests.setTarget(target);
    exe_tests.setBuildMode(mode);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&exe_tests.step);
}

