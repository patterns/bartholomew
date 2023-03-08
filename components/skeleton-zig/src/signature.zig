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

const Signature = @This();

pub const ProduceKeyFn = *const fn (allocator: Allocator, keyProvider: []const u8) PublicKey;

const Impl = struct { produce: ProduceKeyFn };
var impl = SignedByRSAImpl{ .map = undefined, .pubk = undefined };
var produce: ProduceKeyFn = undefined;

// SHA256 hash creates digests of 32 bytes.
const sha256_len: usize = 32;

// extract request header to make a map of signature fields
pub fn init(allocator: Allocator, option: anytype) void {
    const req = option.request;
    const hdr = req.headers;
    var raw: []const u8 = undefined;

    if (hdr.get("signature")) |sig| {
        raw = sig;
    } else {
        log.err("httpsig signature is required", .{});
        impl.map = std.StringHashMap([]const u8).init(allocator);
    }

    impl.map = str.sigPairs(allocator, raw);
}
pub fn deinit() void {
    impl.map.deinit();
}

// user defined steps to retrieve the public key
pub fn attachFetch(fetch: ProduceKeyFn) void {
    produce = fetch;
}
// recreate the sha256 hash
pub fn calculate(allocator: Allocator, option: anytype) ![]u8 {
    const req = option.request;
    const h = req.headers;
    const m = req.method;
    const u = req.uri;
    return impl.recreate(allocator, m, u, h);
}

pub fn verify(allocator: Allocator, hashed: []u8) !bool {
    // _pre-verify_, make the fetch to instantiate a public key
    const key = try produceKey(allocator);
    // impl.Set(public_key);
    impl.pubk = key;
    return impl.verifyPKCS1v15(allocator, hashed);
}
fn produceKey(allocator: Allocator) !PublicKey {
    if (produce != undefined) {
        if (impl.map.get("keyId")) |kp| {
            return produce(allocator, kp);
        } else {
            log.err("http keyId is required, is name case-sensitive?", .{});
        }
    }
    return error.FetchNotDefined;
}

const SignedByRSAImpl = struct {
    const Self = @This();
    map: std.StringHashMap([]const u8),
    pubk: PublicKey,

    // pass in: inbound request headers
    // output: sha256 hash of the input-string (used in signature)
    pub fn recreate(
        self: Self,
        allocator: Allocator,
        method: u8,
        uri: []const u8,
        hdr: std.StringHashMap([]const u8),
    ) ![]u8 {
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
        try formatInputLeader(&input_string, first, method, uri);

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
        var buffer: [sha256_len]u8 = undefined;
        sha.hash(input_string.items, &buffer, sha.Options{});
        return &buffer;
    }

    // hashed: the sha256 hash of the input-string
    // signature: the plain text decoded from header base64 field
    // see https://go.dev/src/crypto/rsa/pkcs1v15.go
    pub fn verifyPKCS1v15(self: Self, allocator: Allocator, hashed: []u8) !bool {
        const info = try pkcs1v15HashInfo(hashed.len);
        const tLen = info.prefix.len + info.hashLen;

        const plain = try self.decodeB64();
        const k = self.pubk.size();

        if (k < tLen + 11) return error.ErrVerification;

        if (k != plain.len) return error.ErrVerification;

        const em = encrypt(self.pubk, plain);
        log.debug("encrypt, {any}", .{em});

        _ = allocator;
        // TODO need to convert []const u8 to []const usize to call big int math
        //const check = iguana.preverify(allocator, self.pubk.N, self.pubk.E, plain);
        //log.debug("preverify, {any}", .{ check });

        return true;
    }

    // The signature becomes the length of the SHA256 hash after base64 decoding.
    // We're basically unwrapping or reversing the steps from the signing.
    fn decodeB64(self: Self) ![]u8 {
        if (self.map.get("signature")) |sig| {
            const sz = try b64.calcSizeForSlice(sig);
            if (sha256_len < sz) {
                log.err("Perhaps SHA256 wasn't the hash used by signer, sz: {d}", .{sz});
                return error.SignatureDecode;
            }
            var buffer: [sha256_len]u8 = std.mem.zeroes([sha256_len]u8);
            var decoded = buffer[0..sz];
            try b64.decode(decoded, sig);

            return decoded;
        }

        log.err("httpsig signature is required", .{});
        return error.SignatureAbsent;
    }
};

pub fn fromPEM(allocator: Allocator, pem: []const u8) !PublicKey {
    var start: usize = undefined;
    var stop: usize = undefined;
    if (std.mem.indexOf(u8, pem, "-----BEGIN PUBLIC KEY-----")) |index| {
        start = index;
    }
    if (std.mem.indexOf(u8, pem, "-----END PUBLIC KEY-----")) |index| {
        stop = index;
    }
    log.debug("pem hd/footer sanity checks, ", .{});
    if (start == undefined or stop == undefined) return error.UnknownPEM;
    //const offset = start + 26;
    //const mid = pem[offset..stop];
    //var sz = std.mem.replacementSize(u8, mid, "\n", "");
    //var buffer = try allocator.alloc(u8, sz);
    //defer allocator.free(buffer);
    //var count = std.mem.replace(u8, pem, "\n", "", buffer);
    //log.debug("pem newlines, {d}", .{ count });
    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    var clean: []const u8 = undefined;
    var iter = std.mem.tokenize(u8, pem, "\n");
    while (iter.next()) |line| {
        clean = std.mem.trim(u8, line, "\n");
        if (str.eq("-----END PUBLIC KEY-----", clean)) break;
        if (str.eq("-----BEGIN PUBLIC KEY-----", clean)) continue;
        buffer.appendSlice(clean) catch {
            log.err("pem read buffer OutOfMem", .{});
            return error.BufferMemByPEM;
        };
    }

    var sz = b64.calcSizeForSlice(buffer.items) catch {
        log.err("pem size calc", .{});
        return error.BufferMemByPEM;
    };
    var bufdco = allocator.alloc(u8, sz) catch {
        log.err("pem alloc", .{});
        return error.BufferMemByPEM;
    };
    var decoded = bufdco[0..sz];
    b64.decode(decoded, buffer.items) catch {
        log.err("pem base64 decode", .{});
        return error.BufferMemByPEM;
    };

    var key = std.crypto.Certificate.rsa.PublicKey.parseDer(decoded) catch {
        log.err("pem pubkey parse", .{});
        return error.BufferMemByPEM;
    };
    log.debug("E:{d}, N: {any}", .{ key.exponent, key.modulus });

    // TODO are the bytes copied (free bufdco?)
    return PublicKey{
        .N = key.modulus,
        .E = key.exponent,
    };
}

fn pkcs1v15HashInfo(inLen: usize) !HashInfo {
    if (sha256_len != inLen) return error.NotHashedBySHA256;

    var info = HashInfo{
        .prefix = hashPrefixes(),
        .hashLen = sha256_len,
    };

    return info;
}

fn encrypt(pubk: anytype, plaintext: []u8) []const u8 {
    //const N = bigmod.NewModulusFromBig(pubk.modulus);
    //const m = bigmod.NewNat().SetBytes(plaintext, N);

    log.debug("TODO {any}, {any}", .{ pubk, plaintext });
    return "TO-BE-CONTINUED";
}

// TODO use std.crypto.Certificate.rsa.PublicKey
pub const PublicKey = struct {
    const Self = @This();
    N: []const u8, // modulus (big.Int)
    E: []const u8, // exponent (int)

    // modulus size in bytes
    pub fn size(self: Self) usize {
        return self.N.len;
    }
};
const HashInfo = struct {
    prefix: []const u8,
    hashLen: usize,
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
    FetchNotDefined,
    UnknownPEM,
    BufferMemByPEM,
    SignatureKeyId,
    SignatureAbsent,
    SignatureSequence,
    SignatureFormat,
    SignatureHost,
    SignatureDate,
    SignatureDigest,
    SignatureDecode,
};
