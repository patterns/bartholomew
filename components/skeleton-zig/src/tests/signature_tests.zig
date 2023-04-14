const std = @import("std");

const lib = @import("../lib.zig");
const signature = @import("../signature.zig");
// TODO organize imports
const ro = @import("../rows.zig");

//const ed25519 = std.crypto.sign.Ed25519;
const expect = std.testing.expect;
const expectErr = std.testing.expectError;
const expectStr = std.testing.expectEqualStrings;

test "signature base input string minimal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();
    // sim rcv request
    var rcv = lib.SpinRequest{
        .ally = ally,
        .method = @enumToInt(signature.Verb.post),
        .uri = "/foo?param=value&pet=dog",
        .params = undefined,
        .headers = undefined,
        .body = undefined,
    };
    var arr = "{\"hello\": \"world\"}".*;
    var buf: []u8 = &arr;
    var fbs = std.io.fixedBufferStream(buf);
    rcv.body = &fbs;
    // minimal headers
    var raw = minRawHeaders();
    rcv.headers = raw;

    // wrap raw headers
    var wrap = ro.HeaderList.init(ally, raw);
    try wrap.catalog();
    // format sig base input
    try signature.init(ally, raw);
    const base = try signature.fmtBase(rcv, wrap);

    // With the headers specified, our expected signature base input string is:
    try expectStr(
        "(request-target): post /foo?param=value&pet=dog\nhost: example.com\ndate: Sun, 05 Jan 2014 21:31:40 GMT",
        base,
    );
}

test "signature base input string regular" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();
    // sim rcv request
    var rcv = lib.SpinRequest{
        .ally = ally,
        .method = @enumToInt(signature.Verb.post),
        .uri = "/foo?param=value&pet=dog",
        .params = undefined,
        .headers = undefined,
        .body = undefined,
    };
    var arr = "{\"hello\": \"world\"}".*;
    var buf: []u8 = &arr;
    var fbs = std.io.fixedBufferStream(buf);
    rcv.body = &fbs;
    // headers to cover host,date,digest,content-type,content-length
    var raw = regRawHeaders();
    rcv.headers = raw;

    // wrap raw headers
    var wrap = ro.HeaderList.init(ally, raw);
    try wrap.catalog();
    // format sig base input
    try signature.init(ally, raw);
    const base = try signature.fmtBase(rcv, wrap);

    // With the headers specified, our expected signature base input string is:
    try expectStr(
        "(request-target): post /foo?param=value&pet=dog\nhost: example.com\ndate: Sun, 05 Jan 2014 21:31:40 GMT\ncontent-type: application/json\ndigest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\ncontent-length: 18",

        base,
    );
}

test "signature base in the form of SHA256 sum" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();
    // sim rcv request
    var rcv = lib.SpinRequest{
        .ally = ally,
        .method = @enumToInt(signature.Verb.post),
        .uri = "/foo?param=value&pet=dog",
        .params = undefined,
        .headers = undefined,
        .body = undefined,
    };
    var arr = "{\"hello\": \"world\"}".*;
    var buf: []u8 = &arr;
    var fbs = std.io.fixedBufferStream(buf);
    rcv.body = &fbs;
    // headers to cover host,date,digest,content-type,content-length
    var raw = regRawHeaders();
    rcv.headers = raw;

    // wrap raw headers
    var wrap = ro.HeaderList.init(ally, raw);
    try wrap.catalog();
    // perform calculation
    try signature.init(ally, raw);
    const base = try signature.sha256Base(rcv, wrap);

    var expsum: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expsum, "53CD4050FF72E3A6383091186168F3DF4CA2E6B3A77CBED60A02BA00C9CD8078");

    // With the headers specified, our signature base must be sum:
    try std.testing.expectEqual(expsum, base);
}
////return error.SkipZigTest;

//const test_key_rsa_pss = @embedFile("test-key-rsa-pss.pem");
fn basicPublicKeyRSA(allocator: std.mem.Allocator, proxy: []const u8) signature.PublicKey {
    _ = proxy;
    const key = signature.fromPEM(allocator, pub_key_pem) catch |err| {
        std.debug.panic("PEM decode failed, {!}", .{err});
    };

    return signature.PublicKey{
        .N = key.N,
        .E = key.E,
    };
}

// simulate raw header fields
fn minRawHeaders() ro.RawHeaders {
    var list: ro.RawHeaders = undefined;
    list[0] = ro.RawField{ .fld = "host", .val = "example.com" };
    list[1] = ro.RawField{ .fld = "date", .val = "Sun, 05 Jan 2014 21:31:40 GMT" };
    list[2] = ro.RawField{ .fld = "content-type", .val = "application/json" };
    list[3] = ro.RawField{ .fld = "digest", .val = "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=" };
    list[4] = ro.RawField{ .fld = "content-length", .val = "18" };
    list[5] = ro.RawField{
        .fld = "signature",
        .val = "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"",
    };

    return list;
}

// simulate covered raw headers
fn regRawHeaders() ro.RawHeaders {
    var list: ro.RawHeaders = undefined;
    list[0] = ro.RawField{ .fld = "host", .val = "example.com" };
    list[1] = ro.RawField{ .fld = "date", .val = "Sun, 05 Jan 2014 21:31:40 GMT" };
    list[2] = ro.RawField{ .fld = "content-type", .val = "application/json" };
    list[3] = ro.RawField{ .fld = "digest", .val = "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=" };
    list[4] = ro.RawField{ .fld = "content-length", .val = "18" };
    list[5] = ro.RawField{
        .fld = "signature",
        .val = "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date content-type digest content-length\",signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"",
    };

    return list;
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

