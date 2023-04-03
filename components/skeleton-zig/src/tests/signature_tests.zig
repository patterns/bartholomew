const std = @import("std");

const lib = @import("../lib.zig");
const signature = @import("../signature.zig");
const row = @import("../rows.zig");
const Allocator = std.mem.Allocator;
const ed25519 = std.crypto.sign.Ed25519;
const expect = std.testing.expect;
const expectErr = std.testing.expectError;
const expectStr = std.testing.expectEqualStrings;
const debug = std.debug;

test "subheaders read mapping" {
    var headers = row.HeaderList.init();
    const raw = "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",sub-signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"";

    // To workaround the enum collision, rewrite the signature subheader field-name.

    try headers.read(raw);

    const subheader_keyid = headers.get(.sub_key_id).value;
    try expectStr("Test", subheader_keyid);
    const subheader_algo = headers.get(.sub_algorithm).value;
    try expectStr("rsa-sha256", subheader_algo);
    const subheader_hd = headers.get(.sub_headers).value;
    try expectStr("(request-target) host date", subheader_hd);

    const subheader_sig = headers.get(.sub_signature).value;
    const ally = std.testing.allocator;
    var b64 = std.base64.standard_no_pad.Decoder;
    const max = try b64.calcSizeForSlice(subheader_sig);
    var decoded_orig = try ally.alloc(u8, max);
    var decoded_sub = try ally.alloc(u8, max);

    try b64.decode(
        decoded_orig,
        "qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=",
    );
    try b64.decode(decoded_sub, subheader_sig);
    try std.testing.expectEqual(decoded_orig, decoded_sub);
}

test "signature base input string" {
    //const ally = std.testing.allocator;
    var basic_req = try basicRequest();
    //try signature.init( basic_req.headers );
    //const base_input = try signature.baseInput(ally,
    //    basic_req.headers,
    //    basic_req.method,
    //    basic_req.uri,
    //);

    debug.print("debug {d}\n", .{basic_req.method});
    return error.SkipZigTest;
    //try expectStr(
    //    "(request-target): post /foo?param=value&pet=dog\nhost: example.com\ndate: Sun, 05 Jan 2014 21:31:40 GMT",
    //    base_input,
    //);
}

//const test_key_rsa_pss = @embedFile("test-key-rsa-pss.pem");
fn basicPublicKeyRSA(allocator: Allocator, proxy: []const u8) signature.PublicKey {
    _ = proxy;
    const key = signature.fromPEM(allocator, pub_key_pem) catch |err| {
        debug.panic("PEM decode failed, {!}", .{err});
    };

    return signature.PublicKey{
        .N = key.N,
        .E = key.E,
    };
}

fn basicRequest() !*lib.WReq {
    var headers = row.HeaderList.init();
    var body = try std.BoundedArray(u8, 8192).init(1024);

    const post: u8 = 1;
    const uri = "/foo?param=value&pet=dog";

    _ = try body.writer().write("{\"hello\": \"world\"}");
    try headers.add(.{ .cell_type = .host, .label = "host", .value = "example.com" });
    try headers.add(.{ .cell_type = .date, .label = "date", .value = "Sun, 05 Jan 2014 21:31:40 GMT" });
    try headers.add(.{ .cell_type = .content_type, .label = "content-type", .value = "application/json" });
    try headers.add(.{ .cell_type = .digest, .label = "digest", .value = "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=" });
    try headers.add(.{ .cell_type = .content_length, .label = "content-length", .value = "18" });
    try headers.add(.{
        .cell_type = .signature,
        .label = "signature",
        .value = "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"",
    });
    return newRequest(post, uri, headers, body);
}

fn newRequest(
    method: u8,
    uri: []const u8,
    headers: row.HeaderList,
    body: std.BoundedArray(u8, 8192),
) *lib.WReq {
    var req = lib.WReq{
        .method = method,
        .uri = uri,
        .headers = headers,
        .body = body,
    };

    return &req;
}

const pubPEM =
    \\-----BEGIN PUBLIC KEY-----
    \\MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAlRuRnThUjU8/prwYxbty
    \\WPT9pURI3lbsKMiB6Fn/VHOKE13p4D8xgOCADpdRagdT6n4etr9atzDKUSvpMtR3
    \\CP5noNc97WiNCggBjVWhs7szEe8ugyqF23XwpHQ6uV1LKH50m92MbOWfCtjU9p/x
    \\qhNpQQ1AZhqNy5Gevap5k8XzRmjSldNAFZMY7Yv3Gi+nyCwGwpVtBUwhuLzgNFK/
    \\yDtw2WcWmUU7NuC8Q6MWvPebxVtCfVp/iQU6q60yyt6aGOBkhAX0LpKAEhKidixY
    \\nP9PNVBvxgu3XZ4P36gZV6+ummKdBVnc3NqwBLu5+CcdRdusmHPHd5pHf4/38Z3/
    \\6qU2a/fPvWzceVTEgZ47QjFMTCTmCwNt29cvi7zZeQzjtwQgn4ipN9NibRH/Ax/q
    \\TbIzHfrJ1xa2RteWSdFjwtxi9C20HUkjXSeI4YlzQMH0fPX6KCE7aVePTOnB69I/
    \\a9/q96DiXZajwlpq3wFctrs1oXqBp5DVrCIj8hU2wNgB7LtQ1mCtsYz//heai0K9
    \\PhE4X6hiE0YmeAZjR0uHl8M/5aW9xCoJ72+12kKpWAa0SFRWLy6FejNYCYpkupVJ
    \\yecLk/4L1W0l6jQQZnWErXZYe0PNFcmwGXy1Rep83kfBRNKRy5tvocalLlwXLdUk
    \\AIU+2GKjyT3iMuzZxxFxPFMCAwEAAQ==
    \\-----END PUBLIC KEY-----
;

const pub_key_pem =
    \\-----BEGIN PUBLIC KEY-----
    \\MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
    \\6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
    \\Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
    \\oYi+1hqp1fIekaxsyQIDAQAB
    \\-----END PUBLIC KEY-----
;

// TODO try more examples from the draft
// (https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-16)

