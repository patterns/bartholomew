const std = @import("std");
const cow_list = std.build.Pkg{ .name = "cow_list", .source = .{ .path = "libs/zigstr/libs/cow_list/src/main.zig" } };
const ziglyph = std.build.Pkg{ .name = "ziglyph", .source = .{ .path = "libs/zigstr/libs/ziglyph/src/ziglyph.zig" } };
const Zigstr = std.build.Pkg{
    .name = "Zigstr",
    .source = .{ .path = "libs/zigstr/src/Zigstr.zig" },
    .dependencies = &[_]std.build.Pkg{ cow_list, ziglyph },
};


pub fn build(b: *std.build.Builder) !void {
    const ww = try std.zig.CrossTarget.parse(.{.arch_os_abi = "wasm32-wasi"});
    const target = b.standardTargetOptions(.{.default_target = ww});

    const lib = b.addStaticLibrary("spin", null);
    lib.setBuildMode(std.builtin.Mode.ReleaseSmall);
    lib.setTarget(target);
    lib.linkLibC();
    lib.addIncludePath("libs/spin/http");
    lib.addIncludePath("libs/spin/redis");
    lib.addCSourceFiles(&.{
        "libs/spin/http/spin-http.c",
        "libs/spin/http/wasi-outbound-http.c",
        "libs/spin/redis/outbound-redis.c",
        ////"libs/spin/redis/spin-redis.c",
    }, &.{
        "-Wall",
        "-Wno-unused-parameter",
        "-Wno-switch-bool",
    });

    const exe = b.addExecutable("webcomponent", "src/main.zig");
    exe.setBuildMode(std.builtin.Mode.ReleaseSafe);
    exe.setTarget(target);
    exe.install();
    exe.linkLibC();
    exe.linkLibrary(lib);
    exe.addPackage(Zigstr);
    exe.addIncludePath("libs/spin/http");
    exe.addIncludePath("libs/spin/redis");


    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);
}
