const std = @import("std");
const bld = std.build;

// export symbols (in 0.11 see zig/issues/14139)
const export_names = [_][]const u8 {
        "canonical_abi_free",
        "canonical_abi_realloc",
        "handle-http-request",
};

pub fn build(b: *bld.Builder) !void {
    const ct = try std.zig.CrossTarget.parse(.{.arch_os_abi = "wasm32-wasi"});
    const to = b.standardTargetOptions(.{.default_target = ct});
    ////const to = b.standardTargetOptions(.{});
    const oo = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(optMain(.{.target=to, .optimize=oo}));
    exe.single_threaded = true;
    exe.export_symbol_names = &export_names;
    exe.install();

    // Creates a step for unit testing.
    const main_tests = b.addTest(optTesting(.{.target=to, .optimize=oo}));

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build test`
    // This will evaluate the `test` step rather than the default, which is "install".
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&main_tests.step);
}

fn optMain(option: anytype) bld.ExecutableOptions {
    return bld.ExecutableOptions {
        .name = "timothy",
        .root_source_file = bld.FileSource { .path = "src/main.zig"},
        .target = option.target,
        .optimize = option.optimize,
    };
}

fn optTesting(option: anytype) bld.TestOptions {
    return bld.TestOptions {
        .root_source_file = bld.FileSource { .path = "src/tests.zig"},
        .target = option.target,
        .optimize = option.optimize,
    };
}

