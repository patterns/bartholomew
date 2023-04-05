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
const ally = std.testing.allocator;

test "subheaders read mapping" {
    // simulate raw header values
    var list = row.SourceHeaders{};
    try list.append(ally, [2][]const u8{
        "signature",
        "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"",
    });
    // subheaders wrapper around SegmentedList
    var subheaders = row.SignatureList.init();
    try subheaders.preverify(list);
    //
    // To workaround the enum collision, rewrite the signature subheader field-name.
    // TODO refactor to handle the subheader type as distinct to avoid hiding
    //      and forgetting what this is about..... (because we will forget tomorrow)
    //

    const sh_keyid = subheaders.get(.sub_key_id).value;
    try expectStr("Test", sh_keyid);
    const sh_algo = subheaders.get(.sub_algorithm).value;
    try expectStr("rsa-sha256", sh_algo);
    const sh_hd = subheaders.get(.sub_headers).value;
    try expectStr("(request-target) host date", sh_hd);

    const sh_sig = subheaders.get(.sub_signature).value;
    var b64 = std.base64.standard.Decoder;
    var decoded_orig: [256]u8 = undefined;
    var decoded_sub: [256]u8 = undefined;

    try b64.decode(
        &decoded_orig,
        "NtIKWuXjr4SBEXj97gbick4O95ff378I0CZOa2VnIeEXZ1itzAdqTpSvG91XYrq5CfxCmk8zz1Zg7ZGYD+ngJyVn805r73rh2eFCPO+ZXDs45Is/Ex8srzGC9sfVZfqeEfApRFFe5yXDmANVUwzFWCEnGM6+SJVmWl1/jyEn45qA6Hw+ZDHbrbp6qvD4N0S92jlPyVVEh/SmCwnkeNiBgnbt+E0K5wCFNHPbo4X1Tj406W+bTtnKzaoKxBWKW8aIQ7rg92zqE1oqBRjqtRi5/Q6P5ZYYGGINKzNyV3UjZtxeZNnNJ+MAnWS0mofFqcZHVgSU/1wUzP7MhzOKLca1Yg==",
    );
    try b64.decode(&decoded_sub, sh_sig);

    try std.testing.expectEqual(decoded_orig, decoded_sub);
}

test "signature base input string" {
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

fn basicRequest() !*lib.SpinRequest {
    const post: u8 = 1;
    const uri = "/foo?param=value&pet=dog";
    var body = std.ArrayList(u8).init(ally);
    _ = try body.writer().write("{\"hello\": \"world\"}");

    // simulate raw header values
    var list = row.SourceHeaders{};
    try list.append(ally, [2][]const u8{ "host", "example.com" });
    try list.append(ally, [2][]const u8{ "date", "Sun, 05 Jan 2014 21:31:40 GMT" });
    try list.append(ally, [2][]const u8{ "content-type", "application/json" });
    try list.append(ally, [2][]const u8{ "digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=" });
    try list.append(ally, [2][]const u8{ "content-length", "18" });
    try list.append(ally, [2][]const u8{
        "signature",
        "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"",
    });

    return newRequest(post, uri, list, body);
}

fn newRequest(
    method: u8,
    uri: []const u8,
    headers: row.SourceHeaders,
    body: std.ArrayList(u8),
) *lib.SpinRequest {
    var req = lib.SpinRequest{
        .method = method,
        .uri = uri,
        .headers = headers,
        .body = body,
        .ally = ally,
        .params = row.SourceHeaders{},
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

