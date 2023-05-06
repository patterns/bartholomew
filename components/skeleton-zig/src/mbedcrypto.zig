const std = @import("std");
const c = @cImport({
    @cInclude("mbedtls/bignum.h");
    @cInclude("mbedtls/md.h");
    @cInclude("mbedtls/rsa.h");
});

// Call into MbedTLS Crypto (C) library
pub fn pkcs1Verify(
    hashed: [*]u8,
    sig: [*]const u8,
    N: [:0]const u8,
    E: [:0]const u8,
) !void {
    //hashed is the sha256 sum of message (32 bytes assumed here)
    //sig is the signature supplied to us in the header
    //todo N,E sanity checks
    //todo better errors for debug

    var rsa_context: c.mbedtls_rsa_context = undefined;
    var mpi_n: c.mbedtls_mpi = undefined;
    var mpi_e: c.mbedtls_mpi = undefined;
    c.mbedtls_rsa_init(&rsa_context);
    c.mbedtls_mpi_init(&mpi_n);
    c.mbedtls_mpi_init(&mpi_e);
    defer c.mbedtls_rsa_free(&rsa_context);
    defer c.mbedtls_mpi_free(&mpi_n);
    defer c.mbedtls_mpi_free(&mpi_e);

    const read_n = c.mbedtls_mpi_read_string(&mpi_n, 16, N);
    const read_e = c.mbedtls_mpi_read_string(&mpi_e, 16, E);
    if (read_n != 0 or read_e != 0) return error.PublicKeyRead;

    // assign N and E public key fields
    _ = c.mbedtls_rsa_import(&rsa_context, &mpi_n, null, null, null, &mpi_e);
    const ready = c.mbedtls_rsa_complete(&rsa_context);
    if (ready != 0) return error.PublicKeyInit;

    // invoke MbedTLS (C) lib's verify
    const ret = c.mbedtls_rsa_pkcs1_verify(
        &rsa_context,
        c.MBEDTLS_MD_SHA256,
        32,
        hashed,
        sig,
    );

    if (ret != 0) return error.VerifyBad;
}

const cert = std.crypto.Certificate;
test "mbedcrypto pkcs1 verify" {
    var hashed_msg: [32]u8 = undefined;
    const sha = cert.Algorithm.sha256WithRSAEncryption.Hash();
    sha.hash(base_peop_TXT, &hashed_msg, .{});
    // coerce to many-pointer (for C interop)
    const c_hashed: [*]u8 = &hashed_msg;

    var b64 = std.base64.standard.Decoder;
    var decoded: [256]u8 = undefined;
    try b64.decode(&decoded, signature_peop);
    // coerce to many-pointer (for C interop)
    const c_decoded: [*]u8 = &decoded;

    try pkcs1Verify(c_hashed, c_decoded, modulus_peop, "010001");
}

const base_peop_TXT =
    \\(request-target): post /users/oatmeal/inbox
    \\host: mastodon.social
    \\date: Sun, 30 Apr 2023 04:55:37 GMT
    \\digest: SHA-256=a9IYUmhfuVYZQnUuiqFWHhLnxk67FUjWF4W7vewjGKA=
;
const sum256_peop = "9F17D1A9F11C6AFD8AC047A4929E4A6D61CA9E9773E4A9A0FA4B6F33C6FED548";

const modulus_peop = "B2EE5CE4E8E52D18EF25F1712C6229601DCEE9E076408BC21A51F0303CB0CFD91B063412FC3E75836192499DE3BC7CC1E4C4CDFA2A7ED8C08BB77D6D54A5FD0F478C3CD0471564BE6D4BD0EE3783EE40EF7D378BABB5A9778CB8B36464D2851798017AEBAF1EACE47A78B618ECF4F1774DB701272F693AD3D938E8D5CC90EB66D6A247E5612CEDCC49EB3EE9F482377EF87B295187463182B48F7FA17863EC6543743A7F193C5248FF8011EE53AC558FBA6024951FBDA236D0504313C29DDAD6D890299D6383BE23DCF209AC8B8B9DDAF916244A3868DEFB4B4498F8ED40E7506AAE76ACFB3427CD3EE718406E34F0B9EBF5AEB1D39BAC67FCF2BB368A4CD47D";

const signature_peop = "ZooM2n+l3bYVe0lCU0V9kfBz6kLZ+LjjLPeiAoPbYT2FUQflA2ke7tZVmNGzbMKu+ILNrO9JpGlI+ai9fLKvDXbuPjurlZ6Sq9O8xgXJfuLjYY8n7qEil90dhhFa99cTDNR3RV3wk/i5cVLozoNJTJzQnGcCI5Z8MtMy7hi/W/1AR42CwCiP3CalnB0dS8S4cYdKUQnVPYX6cuCkQH7UdzcEUVQovZGZtRZ9dv3uBXlCKY+3k//haezLKtdyVYfkrGDngtS6MBz4Lp0M4LCa5XSwyUcVZ94+hx2ghoXaCiBjWtow02mrAqH9Ud8i/gnyQ9Bl18AmvmMcStcSBHrSQg==";
