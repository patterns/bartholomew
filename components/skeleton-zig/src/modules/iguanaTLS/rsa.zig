const std = @import("std");
const mem = std.mem;
const Allocator = mem.Allocator;
const Sha224 = std.crypto.hash.sha2.Sha224;
const Sha384 = std.crypto.hash.sha2.Sha384;
const Sha512 = std.crypto.hash.sha2.Sha512;
const Sha256 = std.crypto.hash.sha2.Sha256;

//const x509 = @import("x509.zig");
//const SignatureAlgorithm = x509.Certificate.SignatureAlgorithm;
//const asn1 = @import("asn1.zig");

fn rsa(
    allocator: Allocator,
    modulus: std.math.big.int.Const,
    exponent: std.math.big.int.Const,
    base: []const u8,
) !?std.math.big.int.Managed {
    // @TODO Better algorithm, make it faster.
    const curr_base_limbs = try allocator.alloc(
        usize,
        std.math.divCeil(usize, base.len, @sizeOf(usize)) catch unreachable,
    );
    const curr_base_limb_bytes = @ptrCast([*]u8, curr_base_limbs)[0..base.len];
    mem.copy(u8, curr_base_limb_bytes, base);
    mem.reverse(u8, curr_base_limb_bytes);
    var curr_base = (std.math.big.int.Mutable{
        .limbs = curr_base_limbs,
        .positive = true,
        .len = curr_base_limbs.len,
    }).toManaged(allocator);
    defer curr_base.deinit();

    var curr_exponent = try exponent.toManaged(allocator);
    defer curr_exponent.deinit();
    var result = try std.math.big.int.Managed.initSet(allocator, @as(usize, 1));

    // encrypted = signature ^ key.exponent MOD key.modulus
    while (curr_exponent.toConst().orderAgainstScalar(0) == .gt) {
        if (curr_exponent.isOdd()) {
            try result.ensureMulCapacity(result.toConst(), curr_base.toConst());
            try result.mul(result.toConst(), curr_base.toConst());
            try llmod(&result, modulus);
        }
        try curr_base.sqr(curr_base.toConst());
        try llmod(&curr_base, modulus);
        try curr_exponent.shiftRight(curr_exponent, 1);
    }

    if (result.limbs.len * @sizeOf(usize) < base.len)
        return null;
    return result;
}

// res = res mod N
fn llmod(res: *std.math.big.int.Managed, n: std.math.big.int.Const) !void {
    var temp = try std.math.big.int.Managed.init(res.allocator);
    defer temp.deinit();
    try temp.divTrunc(res, res.toConst(), n);
}

pub fn preverify(
    allocator: Allocator,
    N: []u8,
    E: []u8,
    plaintext: []const u8,
) !bool {
    // RSA hash verification with PKCS 1 V1_5 padding
    const modulus = std.math.big.int.Const{ .limbs = N, .positive = true };
    const exponent = std.math.big.int.Const{ .limbs = E, .positive = true };

    var result = (try rsa(allocator, modulus, exponent, plaintext)) orelse return false;
    defer result.deinit();

    //if (rsa_result.limbs.len * @sizeOf(usize) < signature.data.len)
    //    return false;

    //const enc_buf = @ptrCast([*]u8, rsa_result.limbs.ptr)[0..signature.data.len];
    //mem.reverse(u8, enc_buf);

    //if (enc_buf[0] != 0x00 or enc_buf[1] != 0x01)
    //    return false;
    //if (!mem.endsWith(u8, enc_buf, hash))
    //    return false;
    //if (!mem.endsWith(u8, enc_buf[0 .. enc_buf.len - hash.len], prefix))
    //    return false;
    //if (enc_buf[enc_buf.len - hash.len - prefix.len - 1] != 0x00)
    //    return false;
    //for (enc_buf[2 .. enc_buf.len - hash.len - prefix.len - 1]) |c| {
    //    if (c != 0xff) return false;
    //}

    return true;
}
