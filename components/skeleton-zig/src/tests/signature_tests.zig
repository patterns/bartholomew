const std = @import("std");

const lib = @import("../lib.zig");
const signature = @import("../signature.zig");
// TODO organize imports
const row = @import("../rows.zig");
const Allocator = std.mem.Allocator;
const ed25519 = std.crypto.sign.Ed25519;
const expect = std.testing.expect;
const expectErr = std.testing.expectError;
const expectStr = std.testing.expectEqualStrings;

test "signature base input string" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();

    // simulate request
    var basic_req = try basicRequest(ally);
    // wrap raw headers
    var wrap = row.HeaderList.init(ally, basic_req.headers);
    defer wrap.deinit();
    try wrap.catalog();

    try signature.init(ally, basic_req.headers);
    const base_input = try signature.baseInput(
        ally,
        wrap,
        basic_req.method,
        basic_req.uri,
    );

    try expectStr(
        "(request-target): post /foo?param=value&pet=dog\nhost: example.com\ndate: Sun, 05 Jan 2014 21:31:40 GMT",
        base_input,
    );
    //return error.SkipZigTest;
}

//const test_key_rsa_pss = @embedFile("test-key-rsa-pss.pem");
fn basicPublicKeyRSA(allocator: Allocator, proxy: []const u8) signature.PublicKey {
    _ = proxy;
    const key = signature.fromPEM(allocator, pub_key_pem) catch |err| {
        std.debug.panic("PEM decode failed, {!}", .{err});
    };

    return signature.PublicKey{
        .N = key.N,
        .E = key.E,
    };
}

fn basicRequest(ally: Allocator) !*lib.SpinRequest {
    const post: u8 = 1;
    const uri = "/foo?param=value&pet=dog";
    var arr = "{\"hello\": \"world\"}".*;
    var buf: []u8 = &arr;
    var body = std.io.fixedBufferStream(buf);

    // simulate raw header fields
    var list = row.RawHeaders{};
    try list.append(ally, .{ .field = "host", .value = "example.com" });
    try list.append(ally, .{ .field = "date", .value = "Sun, 05 Jan 2014 21:31:40 GMT" });
    try list.append(ally, .{ .field = "content-type", .value = "application/json" });
    try list.append(ally, .{ .field = "digest", .value = "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=" });
    try list.append(ally, .{ .field = "content-length", .value = "18" });
    try list.append(ally, .{
        .field = "signature",
        .value = "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"",
    });

    return newRequest(ally, post, uri, list, &body);
}

fn newRequest(
    ally: Allocator,
    method: u8,
    uri: []const u8,
    headers: row.RawHeaders,
    body: *std.io.FixedBufferStream([]u8),
) *lib.SpinRequest {
    var req = lib.SpinRequest{
        .ally = ally,
        .method = method,
        .uri = uri,
        .headers = headers,
        .body = body,
        .params = row.RawHeaders{},
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

