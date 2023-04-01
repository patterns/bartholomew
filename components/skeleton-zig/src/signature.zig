const std = @import("std");

const str = @import("strings.zig");
const row = @import("rows.zig");
const exp = @import("modules/rsa/snippet.zig");
const mem = std.mem;
const Allocator = mem.Allocator;
const b64 = std.base64.standard.Decoder;
const log = std.log;

// TODO ?outbound http need to be enabled per destination
//      which may make it impossible to allow every possible site of the public PEM key
//      (maybe we want to make a proxy that handles the trip to these destinations)
//      so use a configuration setting to allow toggling.

const Signature = @This();

pub const ProduceKeyFn = *const fn (allocator: Allocator, keyProvider: []const u8) PublicKey;

const Impl = struct { produce: ProduceKeyFn };
var impl = SignedByRSAImpl{ .map = undefined, .publicKey = undefined };
var produce: ProduceKeyFn = undefined;

// SHA256 hash creates digests of 32 bytes.
const sha256_len: usize = 32;

pub fn init(headers: row.HeaderList) !void {
    const sub_headers = headers.get(.signature).value;
    impl.map = row.SignatureList.init();
    try impl.map.read(sub_headers);
}

// user defined steps to retrieve the public key
pub fn attachFetch(fetch: ProduceKeyFn) void {
    produce = fetch;
}
// recreate the sha256 hash
pub fn calculate(allocator: Allocator, option: anytype) ![]u8 {
    const req = option.request;
    const h = option.refactorInProgress;
    const m = req.method;
    const u = req.uri;

    const base_input = try impl.recreate(allocator, m, u, h);
    const sha = std.crypto.hash.sha2.Sha256;
    var buffer: [sha256_len]u8 = undefined;
    sha.hash(base_input, &buffer, sha.Options{});
    return &buffer;
}
// recreate the signature base input
pub fn baseInput(
    allocator: Allocator,
    headers: row.HeaderList,
    method: u8,
    uri: []const u8,
) ![]u8 {
    return impl.recreate(allocator, method, uri, headers);
}

pub fn verify(allocator: Allocator, hashed: []u8) !bool {
    // _pre-verify_, make the fetch to instantiate a public key
    const key = try produceKey(allocator);
    // impl.Set(public_key);
    impl.publicKey = key;

    // TODO this is the rsa verify that we started,
    // but needs to be replaced by the version from std.crypto.Certificate
    return impl.verifyPKCS1v15(hashed);
}
fn produceKey(allocator: Allocator) !PublicKey {
    if (produce != undefined) {
        const kp = impl.map.get(.sub_key_id).value;
        return produce(allocator, kp);
    }
    return error.FetchNotDefined;
}

const SignedByRSAImpl = struct {
    const Self = @This();

    map: row.SignatureList,
    publicKey: PublicKey,

    // pass in: inbound request headers
    // output: sha256 hash of the input-string (used in signature)
    pub fn recreate(
        self: Self,
        allocator: Allocator,
        method: u8,
        uri: []const u8,
        headers: row.HeaderList,
    ) ![]u8 {
        var recipe = self.map.get(.sub_headers).value;

        var iter = mem.split(u8, recipe, " ");
        var input_string = std.ArrayList(u8).init(allocator);
        ////defer input_string.deinit();
        const writer = input_string.writer();

        // reconstruct input-string
        const first = iter.first();
        try formatInputLeader(&input_string, first, method, uri);

        while (iter.next()) |field| {
            if (str.eq("host", field)) {
                const name = headers.get(.host).value;
                try writer.print("\nhost: {s}", .{name});
            } else if (str.eq("date", field)) {
                //todo check timestamp
                const date = headers.get(.date).value;
                try writer.print("\ndate: {s}", .{date});
            } else if (str.eq("digest", field)) {
                //todo check digest
                const digest = headers.get(.digest).value;
                try writer.print("\ndigest: {s}", .{digest});

                //} else {
                // TODO refactor w mal
                //const val = hdr.get(field) orelse "00000";
                //try writer.print("\n{s}: {s}", .{ field, val });
            }
        }

        //TODO
        // _minimum_ required elements are date, host, and digest (method != get)
        // it's an hard error when any are missing.

        return input_string.items;
    }

    // hashed: the SHA-256 hash of the input-string (signature base)
    // signature: the plain text decoded from header base64 field
    // see https://go.dev/src/crypto/rsa/pkcs1v15.go
    pub fn verifyPKCS1v15(self: Self, hashed: []u8) !bool {
        const info = try pkcs1v15HashInfo(hashed.len);
        const tLen = info.prefix.len + info.hashLen;

        const plain = try self.decodeB64();
        const k = self.publicKey.size();

        if (k < tLen + 11) return error.ErrVerification;

        // TODO double-confirm logic
        ////if (k != plain.len) return error.ErrVerification;

        // DEBUG DEBUG
        try exp.snippet.verifyRsa(std.crypto.hash.sha2.Sha256, hashed[0..sha256_len].*, plain, self.publicKey.N, self.publicKey.E);

        log.debug("did it REALLY work finally?!", .{});

        return true;
    }

    // The signature becomes the length of the SHA256 hash after base64 decoding.
    // We're basically unwrapping or reversing the steps from the signing.
    fn decodeB64(self: Self) ![]u8 {
        const sig = self.map.get(.sub_signature).value;
        const sz = try b64.calcSizeForSlice(sig);
        // TODO double-confirm this logic because I must have read the Golang wrong
        //if (sha256_len < sz) {
        //    log.err("Perhaps SHA256 wasn't the hash used by signer, sz: {d}", .{sz});
        //    return error.SignatureDecode;
        //}
        //var buffer: [sha256_len]u8 = mem.zeroes([sha256_len]u8);
        var buffer: [128]u8 = mem.zeroes([128]u8);
        var decoded = buffer[0..sz];
        try b64.decode(decoded, sig);

        return decoded;
    }
};

// Open PEM envelope to find DER of SubjectPublicKeyInfo
pub fn fromPEM(allocator: Allocator, pem: []const u8) !struct {
    N: []const u8,
    E: []const u8,
} {
    // sanity check as this is not for every case of PEM
    var start: usize = undefined;
    var stop: usize = undefined;
    if (mem.indexOf(u8, pem, "-----BEGIN PUBLIC KEY")) |index| {
        start = index;
    } else {
        return error.UnknownPEM;
    }
    if (mem.indexOf(u8, pem, "-----END PUBLIC KEY")) |index| {
        stop = index;
    } else {
        return error.UnknownPEM;
    }

    var buffer = std.ArrayList(u8).init(allocator);
    defer buffer.deinit();
    var clean: []const u8 = undefined;
    var iter = mem.tokenize(u8, pem, "\n");
    while (iter.next()) |line| {
        clean = mem.trim(u8, line, "\n");
        if (mem.startsWith(u8, clean, "-----END PUBLIC KEY")) break;
        if (mem.startsWith(u8, clean, "-----BEGIN PUBLIC KEY")) continue;
        try buffer.appendSlice(clean);
    }

    var sz = try b64.calcSizeForSlice(buffer.items);
    var bufdco = try allocator.alloc(u8, sz);
    //defer allocator.free(bufdco);
    var decoded = bufdco[0..sz];
    try b64.decode(decoded, buffer.items);

    // does the DER slice begin with 0x30? (sequence_tag); 48 in decimal
    const begin = decoded[0];
    if (begin != 0x30) return error.UnknownX509KeySpec;

    const hint = decoded[1];
    var first_index: usize = 0;
    var length: usize = 0;
    // can be 1/2/3 bytes to represent length; larger than 127 will be multi byte
    if (hint <= 0x7F) {
        first_index = 2;
        length = hint;
        log.debug("der length, single byte {d}", .{hint});
    } else if (hint == 0x81) {
        first_index = 3;
        length = decoded[2];
        log.debug("der length, double byte {d}", .{length});
    } else if (hint == 0x82) {
        first_index = 4;
        const hi_bits: usize = decoded[2];
        const lo_bits: usize = decoded[3];
        const shifted = @shlExact(hi_bits, @bitSizeOf(u8));
        length = shifted | lo_bits;
        log.debug("der length, triple byte {d}", .{length});
    } else {
        log.err("der length exceeded", .{});
        std.debug.assert(unreachable);
    }

    // SPKI is after the length encoding
    const last_index = first_index + length;
    const spki = decoded[first_index..last_index];

    // at algorithm-identifier (OID)
    //const rsa_alg = [_]u8{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
    var check: []u8 = undefined;
    var bit_str: []u8 = undefined;
    var data: []u8 = undefined;

    //TODO debug more safety on N/E
    var key_tuple: struct { E: []const u8, N: []const u8 } = undefined;
    const tag = spki[0];
    if (tag == 0x30 and spki[1] == 0x0D) {
        // tag means sequence and 0x0D means field is 13 bytes
        //if (mem.eql(u8, &rsa_alg, spki[2..14])) {
        check = spki[2..14];
        bit_str = spki[15..];
        // should begin 0x03 and length
        if (bit_str[0] == 0x03 and bit_str[1] == 0x82) {
            const hi_bits: usize = bit_str[2];
            const lo_bits: usize = bit_str[3];
            const shifted: usize = @shlExact(hi_bits, @bitSizeOf(u8));
            length = shifted | lo_bits;
            //const stop_index = 5 + length;
            //data = bit_str[5..stop_index];

            data = bit_str[5..];
            const tmp = try std.crypto.Certificate.rsa.PublicKey.parseDer(data);
            key_tuple = .{ .E = tmp.exponent, .N = tmp.modulus };
        }
        //}
    }

    log.debug("pub N: {any}, E: {any}", .{ key_tuple.N, key_tuple.E });

    return .{ .N = key_tuple.N, .E = key_tuple.E };
}

fn pkcs1v15HashInfo(inLen: usize) !HashInfo {
    if (sha256_len != inLen) return error.NotHashedBySHA256;

    var info = HashInfo{
        .prefix = hashPrefixes(),
        .hashLen = sha256_len,
    };

    return info;
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
    // TODO double-check this, seen docs that begin with other subheaders
    if (!mem.startsWith(u8, first, "(request-target)")) {
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
    UnknownX509KeySpec,
    SignatureKeyId,
    SignatureAbsent,
    SignatureSequence,
    SignatureFormat,
    SignatureHost,
    SignatureDate,
    SignatureDigest,
    SignatureDecode,
};
