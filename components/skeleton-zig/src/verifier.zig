const std = @import("std");

const snip = @import("modules/rsa/snippet.zig");
const lib = @import("lib.zig");
const prm = @import("params.zig");
const mem = std.mem;
const Allocator = mem.Allocator;
const b64 = std.base64.standard.Decoder;
const log = std.log;
const streq = std.ascii.eqlIgnoreCase;

// Reminder, _Verifier_ rename here is to emphasize that our concern is
// only the public key; at the same time, we are not making a general purpose
// public key, this verifier is limited to ActivityPub and the HTTP signature
// in Mastodon server crosstalk.
const Verifier = @This();

const Impl = struct { produce: ProduceVerifierFn };
var impl = ByRSASignerImpl{ .auth = undefined, .publicKey = undefined };
var produce: ProduceVerifierFn = undefined;

pub fn init(ally: Allocator, raw: prm.RawHeaders) !void {
    impl.auth = prm.AuthParams.init(ally, raw);
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
pub fn sha256Base(req: lib.SpinRequest, headers: prm.HeaderList) ![sha256_len]u8 {
    var buffer: [sha256_len]u8 = undefined;
    const base = try impl.fmtBase(@intToEnum(Verb, req.method), req.uri, headers);
    std.crypto.hash.sha2.Sha256.hash(base, &buffer, .{});
    return buffer;
}

// reconstruct the signature base input str
pub fn fmtBase(req: lib.SpinRequest, headers: prm.HeaderList) ![]const u8 {
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

    auth: prm.AuthParams,
    publicKey: std.crypto.Certificate.rsa.PublicKey,

    // reconstruct input-string
    pub fn fmtBase(
        self: Self,
        verb: Verb,
        uri: []const u8,
        headers: prm.HeaderList,
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
                const kind = prm.Kind.fromDescr(base_el);
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

// Open PEM envelope and convert DER to SubjectPublicKeyInfo
pub fn fromPEM(pem: std.io.FixedBufferStream([]const u8).Reader, ally: Allocator) !std.crypto.Certificate.rsa.PublicKey {
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

    var decoded: [512]u8 = undefined;
    try b64.decode(&decoded, fbs.getWritten());
    // TODO should we return decoded here to allow a unit test?
    // here, look at letsencrypt.org article "A Warm Welcome to ASN1 and DER"
    // type-length-value should be 0x30 first for the sequence tag
    if (decoded[0] != 0x30) return error.Asn1SequenceTag;
    // todo bit set to check 8th bit (128)?

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
    ////const rsa_alg = [_]u8{ 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00 };
    var check: []u8 = undefined;
    var bit_str: []u8 = undefined;
    var data: []u8 = undefined;

    //TODO debug more safety on N/E

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
            return std.crypto.Certificate.rsa.PublicKey.fromBytes(data, tmp.modulus, ally);
        }
        //}
    }

    return error.PublicKeyPemParse;
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
