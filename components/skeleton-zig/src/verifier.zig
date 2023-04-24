const std = @import("std");

const snip = @import("modules/rsa/snippet.zig");
const lib = @import("lib.zig");
const phi = @import("phi.zig");
const mem = std.mem;
const Allocator = mem.Allocator;
const log = std.log;
const b64 = std.base64.standard.Decoder;
const streq = std.ascii.eqlIgnoreCase;

// Reminder, _Verifier_ rename here is to emphasize that our concern is
// only the public key; at the same time, we are not making a general purpose
// public key, this verifier is limited to ActivityPub and the HTTP signature
// in Mastodon server crosstalk.
const Verifier = @This();

const Impl = struct { produce: ProduceVerifierFn };
var impl = ByRSASignerImpl{ .auth = undefined, .publicKey = undefined };
var produce: ProduceVerifierFn = undefined;

pub fn init(ally: Allocator, raw: phi.RawHeaders) !void {
    impl.auth = phi.AuthParams.init(ally, raw);
    try impl.auth.preverify();
}

pub const ProduceVerifierFn = *const fn (keyProvider: []const u8, ally: Allocator) anyerror!std.crypto.Certificate.rsa.PublicKey;

// user defined step to harvest the verifier (pub key)
pub fn attachFetch(fetch: ProduceVerifierFn) void {
    // usually triggers network trip to the key provider:
    // - in wasi, we designate a proxy because no ACL will be exhaustive
    // - on-premise, can be database retrieve,
    // - in tests, will short circuit (fake/hard-coded)
    produce = fetch;
}

// calculate SHA256 sum of signature base input str
pub fn sha256Base(req: lib.SpinRequest, headers: phi.HeaderList) ![sha256_len]u8 {
    var buffer: [sha256_len]u8 = undefined;
    const base = try impl.fmtBase(@intToEnum(Verb, req.method), req.uri, headers);
    std.crypto.hash.sha2.Sha256.hash(base, &buffer, .{});
    return buffer;
}

// reconstruct the signature base input str
pub fn fmtBase(req: lib.SpinRequest, headers: phi.HeaderList) ![]const u8 {
    return impl.fmtBase(@intToEnum(Verb, req.method), req.uri, headers);
}

pub fn verify(ally: Allocator, hashed: [sha256_len]u8) !bool {
    // _pre-verify_, make the fetch to instantiate a public key
    const key = try produceVerifier(ally);
    // impl.Set(public_key);
    impl.publicKey = key;

    // TODO this is the rsa verify that we started,
    // but needs to be replaced by the version from std.crypto.Certificate
    //return verifyPKCS1v15(hashed);
    log.warn("placeholder, {any}", .{hashed});
    return false;
}

// allows test to fire the fetch event
pub fn produceVerifier(ally: Allocator) !std.crypto.Certificate.rsa.PublicKey {
    if (produce != undefined) {
        const key_provider = impl.auth.get(.sub_key_id).value;
        return produce(key_provider, ally);
    }
    return error.FetchNotDefined;
}

const ByRSASignerImpl = struct {
    const Self = @This();

    auth: phi.AuthParams,
    publicKey: std.crypto.Certificate.rsa.PublicKey,

    // reconstruct input-string
    pub fn fmtBase(
        self: Self,
        verb: Verb,
        uri: []const u8,
        headers: phi.HeaderList,
    ) ![]const u8 {
        // each signature subheader has its value encased in quotes
        const shd = self.auth.get(.sub_headers).value;
        const recipe = mem.trim(u8, shd, "\"");
        var it = mem.tokenize(u8, recipe, " ");

        const first = it.next();
        if (first == null) return error.SignatureDelim;

        // TODO double-check this, seen docs that begin with other subheaders
        if (!mem.startsWith(u8, first.?, "(request-target)")) {
            log.err("Httpsig leader format, {s}", .{first.?});
            return error.SignatureFormat;
        }

        // prep bucket for base elements (multiline)
        var acc: [512]u8 = undefined;
        var chan = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&acc) };
        var out = chan.writer();

        // base leader
        try out.print("{0s}: {1s} {2s}", .{ first.?, verb.toDescr(), uri });
        // base elements
        while (it.next()) |base_el| {
            if (streq("host", base_el)) {
                const name = headers.get(.host).value;
                try out.print("\u{000A}host: {s}", .{name});
            } else if (streq("date", base_el)) {
                //todo check timestamp
                const date = headers.get(.date).value;
                try out.print("\u{000A}date: {s}", .{date});
            } else if (streq("digest", base_el)) {
                //todo check digest
                const digest = headers.get(.digest).value;
                try out.print("\u{000A}digest: {s}", .{digest});
            } else {
                // TODO handle USER-DEFINED
                const kind = phi.Kind.fromDescr(base_el);
                const val = headers.get(kind).value;

                const lower = base_el;
                try out.print("\u{000A}{s}: {s}", .{ lower, val });
            }
        }

        return chan.buffer.getWritten();
    }

    // hashed: the SHA-256 hash of the input-string (signature base)
    // signature: the plain text decoded from header base64 field
    // see https://go.dev/src/crypto/rsa/pkcs1v15.go
    pub fn verifyPKCS1v15(hashed: [sha256_len]u8) !bool {
        //const info = try pkcs1v15HashInfo(hashed.len);
        //const tLen = info.prefix.len + info.hashLen;

        //const plain = try self.decodeB64();
        //const k = self.publicKey.size();

        //if (k < tLen + 11) return error.ErrVerification;

        // TODO double-confirm logic
        ////if (k != plain.len) return error.ErrVerification;

        // DEBUG DEBUG
        //try exp.snippet.verifyRsa(std.crypto.hash.sha2.Sha256,
        //    hashed[0..sha256_len].*, plain,
        //    self.publicKey.n, self.publicKey.e);

        log.debug("did it REALLY work, {any}", .{hashed});

        return false;
    }

    // The signature becomes the length of the SHA256 hash after base64 decoding.
    // We're basically unwrapping or reversing the steps from the signing.
    fn decodeB64(self: Self) ![]u8 {
        const sig = self.auth.get(.sub_signature).value;
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

// namespace short aliases
const cert = std.crypto.Certificate;
const dere = cert.der.Element;

pub fn fromPEM(pem: std.io.FixedBufferStream([]const u8).Reader, ally: Allocator) !cert.rsa.PublicKey {
    const max = comptime maxPEM();
    var buffer: [max]u8 = undefined;
    var fbs = std.io.fixedBufferStream(&buffer);
    var line_buf: [80]u8 = undefined;
    var begin_marker_found = false;
    while (try pem.readUntilDelimiterOrEof(&line_buf, lf_literal)) |line| {
        if (mem.startsWith(u8, line, "-----END ")) break;
        if (mem.startsWith(u8, line, "-----BEGIN ")) {
            // only care about public key
            if (mem.endsWith(u8, line, " PUBLIC KEY-----")) {
                begin_marker_found = true;
            }
            continue;
        }
        if (begin_marker_found) {
            _ = try fbs.write(line);
        }
    }

    const pubpem = fbs.getWritten();
    var der_bytes: [512]u8 = undefined;
    try b64.decode(&der_bytes, pubpem);

    // type-length-value begins 0x30 (sequence tag)
    if (der_bytes[0] != 0x30) return error.Asn1SequenceTag;

    const spki_el = try dere.parse(&der_bytes, 0);
    const algo_el = try dere.parse(&der_bytes, spki_el.slice.start);
    const bits_el = try dere.parse(&der_bytes, algo_el.slice.end);
    const cb = cert{ .buffer = &der_bytes, .index = undefined };
    const pub_key = try cert.parseBitString(cb, bits_el);

    // i think we need a tagged union between Ed25519 and RSA pub-key (w algo_el)
    const pub_slice = cb.buffer[pub_key.start..pub_key.end];
    const pk_components = try cert.rsa.PublicKey.parseDer(pub_slice);

    //log.warn("e {d}, n {any}", .{
    //    std.fmt.fmtSliceHexLower(pk_components.exponent),
    //    std.fmt.fmtSliceHexLower(pk_components.modulus),
    //});
    return try cert.rsa.PublicKey.fromBytes(pub_slice, pk_components.modulus, ally);
}

// Open PEM envelope and convert DER to SubjectPublicKeyInfo
//pub fn fromPEM001(pem: std.io.FixedBufferStream([]const u8).Reader )
// !std.crypto.Certificate.rsa.PublicKey {
//    const len_tup = derLength(&der_bytes, 1, der_size);
// spki starts after length encoding
//    const spki_at: usize = len_tup.eol;
//    const spki_total: usize = len_tup.total;
//    const spki_end = spki_at + spki_total;
//    const spki = der_bytes[spki_at..spki_end];
// algorithm-identifier (OID)
//    const rsa_alg = [_]u8{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };

// type-length-value begins 0x30 (sequence tag)
//    if (spki[0] != 0x30) return error.SpkiSequenceTag;
//    return error.PublicKeyDer;
//}

// extract total length from DER
fn derLength(der: []u8, len_start: usize, der_max: usize) struct { eol: usize, total: usize } {
    var length_marker: usize = len_start + 1;
    var length_total: usize = @intCast(usize, der[len_start]);
    if (length_total < 0x80) {
        // short form of the length (0-127)
        // fits in (low bits of) single byte (der[len_start])
        return .{ .eol = length_marker, .total = length_total };
    }

    // 8th-bit-on means the len slot is counted in bits 7-1
    const more_bytes_count: usize = length_total - 0x80;
    std.debug.assert(more_bytes_count != 0);

    switch (more_bytes_count) {
        1 => {
            log.warn("additional bytes (1)", .{});
            // total is the value in the single byte
            // der[ len_start + 1 ]
            // which should be in the range 128-255
            const len_at = len_start + 1;
            length_marker = len_at + 1;
            length_total = @intCast(usize, der[len_at]);
        },
        2 => {
            log.warn("additional bytes (2)", .{});
            // total is the value in the double byte
            // der[ (len_start + 1) .. (len_start + 2) ]
            // which should be in the range 256-65535
            const len_at = len_start + 1;
            length_marker = len_at + 2;

            const hi_bits: usize = der[len_at];
            const lo_bits: usize = der[len_at + 1];
            const shifted = @shlExact(hi_bits, @bitSizeOf(u8));
            length_total = shifted | lo_bits;
        },
        else => unreachable,
        // if this was reachable, total bytes would be > 65535
        // which is unexpected because 512 bytes is limit atm
    }

    // DER forbids the range where long form overlaps with short
    std.debug.assert(length_total > 127);

    log.warn("eol {d}, total {d} (max {d})", .{ length_marker, length_total, der_max });
    // verify the extracted total is less (or eq) actual data stream
    // where der_max is the actual available (from PEM file).
    std.debug.assert((length_marker + length_total) <= der_max);

    return .{ .eol = length_marker, .total = length_total };
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

// SHA256 creates digests of 32 bytes.
const sha256_len: usize = 32;

// limit of RSA pub key
fn maxPEM() usize {
    // assume 4096 bits is largest RSA
    const count = 512;
    // base64 increases by 24 bits (or 4 x 6bit digits)
    const multi = 4;
    return count * multi;
}

pub const VerifierError = error{
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

// http method / verbs (TODO don't expose publicly if possible)
pub const Verb = enum(u8) {
    get = 0,
    post = 1,
    put = 2,
    delete = 3,
    patch = 4,
    head = 5,
    options = 6,

    // description (name) format of the enum
    pub fn toDescr(self: Verb) [:0]const u8 {
        //return DescrTable[@enumToInt(self)];
        // insted of table, switch
        switch (self) {
            .get => return "get",
            .post => return "post",
            .put => return "put",
            .delete => return "delete",
            .patch => return "patch",
            .head => return "head",
            .options => return "options",
        }
    }

    // convert to enum
    pub fn fromDescr(text: []const u8) Verb {
        for (DescrTable, 0..) |row, rownum| {
            if (streq(row, text)) {
                return @intToEnum(Verb, rownum);
            }
        }
        unreachable;
    }
    // TODO remove the table in favor of switch
    // lookup table with the description
    pub const DescrTable = [@typeInfo(Verb).Enum.fields.len][:0]const u8{
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "head",
        "options",
    };
};

const lf_codept = "\u{000A}";
const lf_literal = 0x0A;
