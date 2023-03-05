const std = @import("std");
const str = @import("strings.zig");
const Allocator = std.mem.Allocator;
const log = std.log;

// TODO ?outbound http need to be enabled per destination
//      which may make it impossible to allow every possible site of the public PEM key
//      (maybe we want to make a proxy that handles the trip to these destinations)
//      so use a configuration setting to allow toggling.

////const MakeKey = fn (uri: []const u8) std.crypto.sign.sha256.PublicKey;
pub const MakeKey = fn (keyId: []const u8) []const u8;
pub fn calculate(allocator: Allocator, option: anytype) ![]const u8 {
    const req = option.request;
    const hdr = req.headers;

    var raw: []const u8 = undefined;
    if (hdr.get("signature")) |sig| {
        raw = sig;
    } else {
        log.err("httpsig signature is required", .{});
        return error.SignatureAbsent;
    }
    var pairs = str.sigPairs(allocator, raw);
    defer pairs.deinit();

    var seq: []const u8 = undefined;
    if (pairs.get("headers")) |place| {
        seq = place;
    } else {
        log.err("httpsig sequence is required", .{});
        return error.SignatureSequence;
    }
    var iter = std.mem.split(u8, seq, " ");
    var input_string = std.ArrayList(u8).init(allocator);
    defer input_string.deinit();
    const writer = input_string.writer();

    // construct input-string according to sequence 'headers'
    const first = iter.first();
    try formatInputLeader(&input_string, first, req.method, req.uri);

    while (iter.next()) |field| {
        if (str.eq("host", field)) {
            if (hdr.get("host")) |name| {
                try writer.print("\nhost: {s}", .{name});
            } else {
                log.err("httpsig host is required\n", .{});
                return error.SignatureHost;
            }
        } else if (str.eq("date", field)) {
            //todo check timestamp
            if (hdr.get("date")) |date| {
                try writer.print("\ndate: {s}", .{date});
            } else {
                log.err("httpsig date is required\n", .{});
                return error.SignatureDate;
            }
        } else if (str.eq("digest", field)) {
            //todo check digest
            if (hdr.get("digest")) |digest| {
                try writer.print("\ndigest: {s}", .{digest});
            } else {
                log.err("httpsig digest is required\n", .{});
                return error.SignatureDigest;
            }
        } else {
            const val = hdr.get(field) orelse "00000";
            try writer.print("\n{s}: {s}", .{ field, val });
        }
    }
    //TODO
    // _minimum_ required elements are date, host, and digest (method != get)
    // it's an hard error when any are missing.

    const sha = std.crypto.hash.sha2.Sha256;
    var buf: [32]u8 = std.mem.zeroes([32]u8);
    sha.hash(input_string.items, &buf, sha.Options{});
    log.debug("sha, {any}\n", .{buf});

    log.debug("httpsig verify flow, {any}\n", .{option.public});
    var proxy: []const u8 = undefined;
    if (pairs.get("keyId")) |svc| {
        proxy = svc;
    } else {
        log.err("httpsig keyId is required\n", .{});
        return error.SignatureKeyId;
    }
    const key = option.key;
    const pubkey = key(proxy);
    log.debug("httpsig key, {any}\n", .{pubkey});

    // follow std lib verify call
    // std.crypto.ecdsa.Signature.verify(buf, pubkey);
    // arguments: public key, hashed msg, signature
    // so far we have: hashed msg, signature
    // - public key needs to be fetched

    log.debug("httpsig input, {s}\n", .{input_string.items});
    //todo allocate if need
    return "PLACEHOLDER";
}

// see https://go.dev/src/crypto/rsa/pkcs1v15.go
fn verifyPKCS1v15(pubk: PublicKey, hashed: []u8, sig: []u8) !bool {
    const info = try pkcs1v15HashInfo(hashed.len);
    log.debug("SHA256 hash length, {d}", .{info.hashLen});

    const tLen = info.prefix.len + info.hashLen;
    const k = pubk.size();

    if (k < tLen + 11) return error.ErrVerification;

    if (k != sig.len) return error.ErrVerification;

    //const em = try encrypt(pubk, sig);

    return true;
}

fn pkcs1v15HashInfo(inLen: usize) !HashInfo {
    // SHA256 hash creates digests of 32 bytes.
    const hashLen: usize = 32;

    if (hashLen != inLen) return error.NotHashedBySHA256;

    var info = HashInfo{
        .prefix = hashPrefixes(),
        .hashLen = hashLen,
    };

    return info;
}

const PublicKey = struct {
    const Self = @This();
    modulus: []const usize,
    exponent: []const usize,

    // modulus size in bytes
    pub fn size(self: Self) usize {
        return self.modulus.len;
    }
};
const HashInfo = struct {
    prefix: []const u8,
    len: usize,
};

fn hashPrefixes() []const u8 {
    // crypto.SHA256
    return &[_]u8{
        0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20,
    };
}

fn formatInputLeader(
    inpstr: *std.ArrayList(u8),
    first: []const u8,
    method: u8,
    uri: []const u8,
) !void {
    if (!std.mem.startsWith(u8, first, "(request-target)")) {
        // input sequence always starts with
        log.err("httpsig hdr unkown format, \n", .{});
        return error.SignatureFormat;
    }

    const verb = fmtMethod(method);
    var writer = inpstr.*.writer();
    try writer.print("{0s}: {1s} {2s}", .{ first, verb, uri });
}

fn fmtMethod(m: u8) []const u8 {
    switch (m) {
        0 => return "get",
        1 => return "post",
        2 => return "put",
        3 => return "delete",
        4 => return "patch",
        5 => return "head",
        6 => return "options",
        else => unreachable,
    }
}

pub const SignatureError = error{
    ErrVerification,
    NotHashedBySHA256,
    SignatureKeyId,
    SignatureAbsent,
    SignatureSequence,
    SignatureFormat,
    SignatureHost,
    SignatureDate,
    SignatureDigest,
};
