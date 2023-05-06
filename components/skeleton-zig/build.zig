const std = @import("std");
const bld = std.build;

// export symbols (in 0.11 see zig/issues/14139)
const export_names = [_][]const u8 {
        "canonical_abi_free",
        "canonical_abi_realloc",
        "handle-http-request",
};
pub fn build(b: *std.Build) !void {
    const ct = try std.zig.CrossTarget.parse(.{.arch_os_abi = "wasm32-wasi"});
    const to = b.standardTargetOptions(.{.default_target = ct});
    const oo = b.standardOptimizeOption(.{});

    const lib = b.addStaticLibrary(.{
        .name = "mbedcrypto",
        .root_source_file = .{ .path = "src/mbedcrypto.zig" },
        .target = to,
        .optimize = oo,
    });

    const libroot = "./src/modules/mbedtls-3.4.0/library/";
    const cflags = [_][]const u8{
        "-std=c99",
        "-Wall",
        "-Wextra",
        "-Wwrite-strings",
        "-Wpointer-arith",
        "-Wimplicit-fallthrough",
        "-Wshadow",
        "-Wvla",
        "-Wformat=2",
        "-Wno-format-nonliteral",
        "-Wmissing-declarations",
        "-Wmissing-prototypes",
        "-Wdocumentation",
        "-Wno-documentation-deprecated-sync",
        "-Wunreachable-code",
    };

    // subset from mbedtls_config.h for pkcs1v15 verify only
    lib.defineCMacro("MBEDTLS_ENTROPY_C", "1");
    lib.defineCMacro("MBEDTLS_HMAC_DRBG_C", "1");
    lib.defineCMacro("MBEDTLS_MD_C", "1");
    lib.defineCMacro("MBEDTLS_SHA512_C", "1");
    lib.defineCMacro("MBEDTLS_SHA256_C", "1");
    lib.defineCMacro("MBEDTLS_RSA_C", "1");
    lib.defineCMacro("MBEDTLS_PKCS1_V15", "1");
    lib.defineCMacro("MBEDTLS_BIGNUM_C", "1");
    lib.defineCMacro("MBEDTLS_OID_C", "1");
    lib.defineCMacro("MBEDTLS_ERROR_C", "1");
    lib.defineCMacro("MBEDTLS_PLATFORM_C", "1");

    const sources = [_][]const u8{

        libroot ++ "entropy.c",
        libroot ++ "hmac_drbg.c",
        libroot ++ "md.c",
        libroot ++ "sha512.c",
        libroot ++ "sha256.c",
        libroot ++ "rsa.c",
        libroot ++ "rsa_alt_helpers.c",
        libroot ++ "bignum.c",
        libroot ++ "bignum_core.c",
        libroot ++ "bignum_mod.c",
        libroot ++ "bignum_mod_raw.c",
        libroot ++ "oid.c",
        libroot ++ "constant_time.c",
        libroot ++ "platform_util.c",
        libroot ++ "error.c",
        libroot ++ "hash_info.c",
        libroot ++ "platform.c",

    };

    for (sources) |src| {
        lib.addCSourceFile(src, &cflags);
    }

    lib.linkLibC();
    lib.addIncludePath("src/modules/mbedtls-3.4.0/include");
    lib.addIncludePath(libroot);

    // This declares intent for the library to be installed into the standard
    // location when the user invokes the "install" step (the default step when
    // running `zig build`).
    b.installArtifact(lib);

    const exe = b.addExecutable(optMain(.{.target=to, .optimize=oo}));
    exe.single_threaded = true;
    exe.export_symbol_names = &export_names;
    exe.linkLibC();
    exe.linkLibrary(lib);
    exe.addIncludePath("src/modules/mbedtls-3.4.0/include");
    b.installArtifact(exe);


    // Creates a step for unit testing. This only builds the test executable
    // but does not run it.
    const main_tests = b.addTest(optTesting(.{.target=to, .optimize=oo}));
    main_tests.linkLibC();
    main_tests.linkLibrary(lib);
    main_tests.addIncludePath("src/modules/mbedtls-3.4.0/include");

    const run_main_tests = b.addRunArtifact(main_tests);

    // This creates a build step. It will be visible in the `zig build --help` menu,
    // and can be selected like this: `zig build test`
    // This will evaluate the `test` step rather than the default, which is "install".
    const test_step = b.step("test", "Run library tests");
    test_step.dependOn(&run_main_tests.step);
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


