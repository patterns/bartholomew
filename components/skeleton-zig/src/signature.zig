const std = @import("std");
const iguana = @import("modules/iguanaTLS/rsa.zig");
const str = @import("strings.zig");
const Allocator = std.mem.Allocator;
const b64 = std.base64.standard.Decoder;
const log = std.log;

// TODO ?outbound http need to be enabled per destination
//      which may make it impossible to allow every possible site of the public PEM key
//      (maybe we want to make a proxy that handles the trip to these destinations)
//      so use a configuration setting to allow toggling.

pub const ProduceKey = fn (keyId: []const u8) []const u8;

const Signature = @This();
var map: std.StringHashMap([]const u8) = undefined;
var produce: ProduceKey = undefined;

// take request and return a map of the signature fields
pub fn init(allocator: Allocator, option: anytype) Signature {
    const req = option.request;
    const hdr = req.headers;
    var raw: []const u8 = undefined;

    if (hdr.get("signature")) |sig| {
        raw = sig;
    } else {
        log.err("httpsig signature is required", .{});
        return Signature{ .map = std.StringHashMap([]const u8).init(allocator) };
    }

    return Signature{
        .map = str.sigPairs(allocator, raw),
    };
}
pub fn deinit(self: Signature) void {
    self.map.deinit();
}
pub fn registerProxy(self: Signature, fetch: ProduceKey) void {
    self.produce = fetch;
}

// pass in: inbound request headers
// output: sha256 hash of the input-string (used in signature)
pub fn calculate(self: Signature, allocator: Allocator, option: anytype) ![sha256_len]u8 {
    const req = option.request;
    const hdr = req.headers;

    var seq: []const u8 = undefined;
    if (self.map.get("headers")) |place| {
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
    var buf: [sha256_len]u8 = std.mem.zeroes([sha256_len]u8);
    sha.hash(input_string.items, &buf, sha.Options{});
    return buf;
}

// SHA256 hash creates digests of 32 bytes.
const sha256_len: usize = 32;
// hashed: the sha256 hash of the input-string
// signature: the plain text decoded from header base64 field
// see https://go.dev/src/crypto/rsa/pkcs1v15.go
pub fn verifyPKCS1v15(self: Signature, allocator: Allocator, hashed: []u8) !bool {
    const info = try pkcs1v15HashInfo(hashed.len);
    const tLen = info.prefix.len + info.hashLen;

    const pubk = try self.produceKey();
    const plain = self.decodeB64();
    const k = pubk.size();

    if (k < tLen + 11) return error.ErrVerification;

    if (k != plain.len) return error.ErrVerification;

    const em = try encrypt(pubk, plain);
    log.debug("encrypt, {any}", .{em});
    const check = iguana.preverify(allocator, pubk.modulus, pubk.exponent, plain);
    log.debug("preverify, {any}", .{check});

    return true;
}
fn produceKey(self: Signature) !PublicKey {
    if (self.produce != undefined) return self.produce();

    return error.ProxyNotRegistered;
}
fn decodeB64(self: Signature) []u8 {
    // TODO ?what size does buffer need (testing 4-digits per)
    if (self.map.get("signature")) |sig| {
        var buffer: [sha256_len * 4]u8 = undefined;
        var decoded = buffer[0..try b64.calcSizeForSlice(sig)];
        try b64.decode(decoded, sig);
        return decoded;
    }

    log.err("httpsig signature is required", .{});
    return "";
}

fn pkcs1v15HashInfo(inLen: usize) !HashInfo {
    if (sha256_len != inLen) return error.NotHashedBySHA256;

    var info = HashInfo{
        .prefix = hashPrefixes(),
        .hashLen = sha256_len,
    };

    return info;
}

fn encrypt(pubk: PublicKey, plaintext: []u8) ![]u8 {
    //const N = bigmod.NewModulusFromBig(pubk.modulus);
    //const m = bigmod.NewNat().SetBytes(plaintext, N);

    log.debug(" {any}, {any}", pubk, plaintext);
    return "TO-BE-CONTINUED";
}

const PublicKey = struct {
    const Self = @This();
    N: []const usize, // modulus (big.Int)
    E: []const usize, // exponent (int)

    // modulus size in bytes
    pub fn size(self: Self) usize {
        return self.N.len;
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
    ProxyNotRegistered,
    SignatureKeyId,
    SignatureAbsent,
    SignatureSequence,
    SignatureFormat,
    SignatureHost,
    SignatureDate,
    SignatureDigest,
};
