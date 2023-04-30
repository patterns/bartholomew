const std = @import("std");
const mem = std.mem;
const crypto = std.crypto;
const cert = crypto.Certificate;
const rsa = cert.rsa;
const BigInt = std.math.big.int.Managed;

pub fn hashed(
    comptime Hash: type,
    message: []const u8,
    pub_key_algo: cert.Parsed.PubKeyAlgo,
    msg_hashed: *[Hash.digest_length]u8,
) !void {
    if (pub_key_algo != .rsaEncryption) return error.CertificateSignatureAlgorithmMismatch;
    Hash.hash(message, msg_hashed, .{});
}

// copied from *std.crypto.Certificate.rsa.verifyRsa* (and hope to remove
// when the standard library offers it publicly scoped)
pub fn signatureProof(
    comptime Hash: type,
    message: []const u8,
    sig: []const u8,
    pub_key_algo: cert.Parsed.PubKeyAlgo,
    pub_key: []const u8,
) !void {
    if (pub_key_algo != .rsaEncryption) return error.CertificateSignatureAlgorithmMismatch;
    const pk_components = try rsa.PublicKey.parseDer(pub_key);
    const exponent = pk_components.exponent;
    const modulus = pk_components.modulus;
    if (exponent.len > modulus.len) return error.CertificatePublicKeyInvalid;
    if (sig.len != modulus.len) return error.CertificateSignatureInvalidLength;

    const hash_der = switch (Hash) {
        crypto.hash.Sha1 => [_]u8{
            0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e,
            0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14,
        },
        crypto.hash.sha2.Sha224 => [_]u8{
            0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05,
            0x00, 0x04, 0x1c,
        },
        crypto.hash.sha2.Sha256 => [_]u8{
            0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05,
            0x00, 0x04, 0x20,
        },
        crypto.hash.sha2.Sha384 => [_]u8{
            0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05,
            0x00, 0x04, 0x30,
        },
        crypto.hash.sha2.Sha512 => [_]u8{
            0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86,
            0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05,
            0x00, 0x04, 0x40,
        },
        else => @compileError("unreachable"),
    };

    var msg_hashed: [Hash.digest_length]u8 = undefined;
    Hash.hash(message, &msg_hashed, .{});

    var rsa_mem_buf: [512 * 64]u8 = undefined;
    var fba = std.heap.FixedBufferAllocator.init(&rsa_mem_buf);
    const ally = fba.allocator();

    switch (modulus.len) {
        inline 128, 256, 512 => |modulus_len| {
            const ps_len = modulus_len - (hash_der.len + msg_hashed.len) - 3;
            const em: [modulus_len]u8 =
                [2]u8{ 0, 1 } ++
                ([1]u8{0xff} ** ps_len) ++
                [1]u8{0} ++
                hash_der ++
                msg_hashed;

            const public_key = rsa.PublicKey.fromBytes(exponent, modulus, ally) catch |err| switch (err) {
                error.OutOfMemory => unreachable, // rsa_mem_buf is big enough
            };
            const em_dec = encrypt(modulus_len, sig[0..modulus_len].*, public_key, ally) catch |err| switch (err) {
                error.OutOfMemory => unreachable, // rsa_mem_buf is big enough

                error.MessageTooLong => unreachable,
                error.NegativeIntoUnsigned => @panic("TODO make RSA not emit this error"),
                error.TargetTooSmall => @panic("TODO make RSA not emit this error"),
                error.BufferTooSmall => @panic("TODO make RSA not emit this error"),
            };

            if (!mem.eql(u8, &em, &em_dec)) {
                return error.CertificateSignatureInvalid;
            }
        },
        else => {
            return error.CertificateSignatureUnsupportedBitCount;
        },
    }
}

////////////

fn encrypt(comptime modulus_len: usize, msg: [modulus_len]u8, public_key: rsa.PublicKey, allocator: std.mem.Allocator) ![modulus_len]u8 {
    var m = try BigInt.init(allocator);
    defer m.deinit();

    try setBytes(&m, &msg, allocator);

    if (m.order(public_key.n) != .lt) {
        return error.MessageTooLong;
    }

    var e = try BigInt.init(allocator);
    defer e.deinit();

    try pow_montgomery(&e, &m, &public_key.e, &public_key.n, allocator);

    var res: [modulus_len]u8 = undefined;

    try toBytes(&res, &e, allocator);

    return res;
}

fn setBytes(r: *BigInt, bytes: []const u8, allcator: std.mem.Allocator) !void {
    try r.set(0);
    var tmp = try BigInt.init(allcator);
    defer tmp.deinit();
    for (bytes) |b| {
        try r.shiftLeft(r, 8);
        try tmp.set(b);
        try r.add(r, &tmp);
    }
}

fn pow_montgomery(r: *BigInt, a: *const BigInt, x: *const BigInt, n: *const BigInt, allocator: std.mem.Allocator) !void {
    var bin_raw: [512]u8 = undefined;
    try toBytes(&bin_raw, x, allocator);

    var i: usize = 0;
    while (bin_raw[i] == 0x00) : (i += 1) {}
    const bin = bin_raw[i..];

    try r.set(1);
    var r1 = try BigInt.init(allocator);
    defer r1.deinit();
    try BigInt.copy(&r1, a.toConst());
    i = 0;
    while (i < bin.len * 8) : (i += 1) {
        if (((bin[i / 8] >> @intCast(u3, (7 - (i % 8)))) & 0x1) == 0) {
            try BigInt.mul(&r1, r, &r1);
            try mod(&r1, &r1, n, allocator);
            try BigInt.sqr(r, r);
            try mod(r, r, n, allocator);
        } else {
            try BigInt.mul(r, r, &r1);
            try mod(r, r, n, allocator);
            try BigInt.sqr(&r1, &r1);
            try mod(&r1, &r1, n, allocator);
        }
    }
}

fn toBytes(out: []u8, a: *const BigInt, allocator: std.mem.Allocator) !void {
    const Error = error{
        BufferTooSmall,
    };

    var mask = try BigInt.initSet(allocator, 0xFF);
    defer mask.deinit();
    var tmp = try BigInt.init(allocator);
    defer tmp.deinit();

    var a_copy = try BigInt.init(allocator);
    defer a_copy.deinit();
    try a_copy.copy(a.toConst());

    // Encoding into big-endian bytes
    var i: usize = 0;
    while (i < out.len) : (i += 1) {
        try tmp.bitAnd(&a_copy, &mask);
        const b = try tmp.to(u8);
        out[out.len - i - 1] = b;
        try a_copy.shiftRight(&a_copy, 8);
    }

    if (!a_copy.eqZero()) {
        return Error.BufferTooSmall;
    }
}

fn mod(rem: *BigInt, a: *const BigInt, n: *const BigInt, allocator: std.mem.Allocator) !void {
    var q = try BigInt.init(allocator);
    defer q.deinit();

    try BigInt.divFloor(&q, rem, a, n);
}

fn countBits(a: std.math.big.int.Const, allocator: std.mem.Allocator) !usize {
    var i: usize = 0;
    var a_copy = try BigInt.init(allocator);
    defer a_copy.deinit();
    try a_copy.copy(a);

    while (!a_copy.eqZero()) {
        try a_copy.shiftRight(&a_copy, 1);
        i += 1;
    }

    return i;
}
