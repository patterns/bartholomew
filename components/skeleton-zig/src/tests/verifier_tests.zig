const std = @import("std");

const lib = @import("../lib.zig");
const vfr = @import("../verifier.zig");
const phi = @import("../phi.zig");
const expect = std.testing.expect;
const expectErr = std.testing.expectError;
const expectStr = std.testing.expectEqualStrings;

// ensure signature base reconstruction works
test "signature base input string minimal" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();
    // sim rcv request
    var rcv = lib.SpinRequest{
        .ally = ally,
        .method = @enumToInt(vfr.Verb.post),
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
    var wrap = phi.HeaderList.init(ally, raw);
    try wrap.catalog();
    // format sig base input
    try vfr.init(ally, raw);
    const base = try vfr.fmtBase(rcv, wrap);

    // With the headers specified, our expected signature base input string is:
    try expectStr(
        "(request-target): post /foo?param=value&pet=dog\nhost: example.com\ndate: Sun, 05 Jan 2014 21:31:40 GMT",
        base,
    );
}

// ensure signature base reconstruction works
test "signature base input string regular" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();
    // sim rcv request
    var rcv = lib.SpinRequest{
        .ally = ally,
        .method = @enumToInt(vfr.Verb.post),
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
    var wrap = phi.HeaderList.init(ally, raw);
    try wrap.catalog();
    // format sig base input
    try vfr.init(ally, raw);
    const base = try vfr.fmtBase(rcv, wrap);

    // With the headers specified, our expected signature base input string is:
    try expectStr(
        "(request-target): post /foo?param=value&pet=dog\nhost: example.com\ndate: Sun, 05 Jan 2014 21:31:40 GMT\ncontent-type: application/json\ndigest: SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=\ncontent-length: 18",

        base,
    );
}

// show correctness of (input params to) SHA256 calculation
test "min signature base in the form of SHA256 sum" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();
    // sim rcv request
    var rcv = lib.SpinRequest{
        .ally = ally,
        .method = @enumToInt(vfr.Verb.post),
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
    var wrap = phi.HeaderList.init(ally, raw);
    try wrap.catalog();

    // perform calculation
    try vfr.init(ally, raw);
    var base = try vfr.sha256Base(rcv, wrap);

    var minsum: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&minsum, "f29e22e3a108abc999f5b0ed27cdb461ca30cdbd3057efa170af52c83dfc0ca6");

    // With the headers specified, our signature base must be sum:
    try std.testing.expectEqual(minsum, base[0..32].*);
}

// show correctness of (input params to) SHA256 calculation
test "reg signature base in the form of SHA256 sum" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();
    // sim rcv request
    var rcv = lib.SpinRequest{
        .ally = ally,
        .method = @enumToInt(vfr.Verb.post),
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
    var wrap = phi.HeaderList.init(ally, raw);
    try wrap.catalog();

    // perform calculation
    try vfr.init(ally, raw);
    var base = try vfr.sha256Base(rcv, wrap);

    var regsum: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&regsum, "53CD4050FF72E3A6383091186168F3DF4CA2E6B3A77CBED60A02BA00C9CD8078");

    // With the headers specified, our signature base must be sum:
    try std.testing.expectEqual(regsum, base[0..32].*);
}

// obtaining the verifier key usually requires a network trip so we make the step
// accept a "harvest" function which is the purpose of this test
test "produce verifier (pub) key" {
    // TODO clean up memory leak
    //const ally = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();

    // minimal headers
    var raw = minRawHeaders();

    // fake public key via our custom harvester
    try vfr.init(ally, raw);
    vfr.attachFetch(produceFromPublicKeyPEM);
    var vkey = try vfr.produceVerifier(ally);

    var int_e: usize = undefined;
    if (vkey.e.fits(usize)) {
        int_e = try vkey.e.to(usize);
    }

    // match known properties of the test key
    try std.testing.expectEqual(int_e, 65537);
}

////    return error.SkipZigTest;

////const test_key_rsa_pss = @embedFile("test-key-rsa-pss.pem");
fn produceFromPublicKeyPEM(proxy: []const u8, ally: std.mem.Allocator) !std.crypto.Certificate.rsa.PublicKey {
    // skip network trip that would normally connect to proxy/provider
    _ = proxy;

    var fbs = std.io.fixedBufferStream(public_key_PEM);

    return vfr.fromPEM(fbs.reader(), ally);
}

// simulate raw header fields
fn minRawHeaders() phi.RawHeaders {
    var list: phi.RawHeaders = undefined;
    list[0] = phi.RawField{ .fld = "host", .val = "example.com" };
    list[1] = phi.RawField{ .fld = "date", .val = "Sun, 05 Jan 2014 21:31:40 GMT" };
    list[2] = phi.RawField{ .fld = "content-type", .val = "application/json" };
    list[3] = phi.RawField{ .fld = "digest", .val = "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=" };
    list[4] = phi.RawField{ .fld = "content-length", .val = "18" };
    list[5] = phi.RawField{
        .fld = "signature",
        .val = "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"",
    };

    return list;
}

// simulate covered raw headers
fn regRawHeaders() phi.RawHeaders {
    var list: phi.RawHeaders = undefined;
    list[0] = phi.RawField{ .fld = "host", .val = "example.com" };
    list[1] = phi.RawField{ .fld = "date", .val = "Sun, 05 Jan 2014 21:31:40 GMT" };
    list[2] = phi.RawField{ .fld = "content-type", .val = "application/json" };
    list[3] = phi.RawField{ .fld = "digest", .val = "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=" };
    list[4] = phi.RawField{ .fld = "content-length", .val = "18" };
    list[5] = phi.RawField{
        .fld = "signature",
        .val = "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date content-type digest content-length\",signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"",
    };

    return list;
}

const test_pub_PEM =
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

var public_key_PEM =
    \\-----BEGIN PUBLIC KEY-----
    \\MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
    \\6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
    \\Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
    \\oYi+1hqp1fIekaxsyQIDAQAB
    \\-----END PUBLIC KEY-----
;

const public_eff_PEM =
    \\-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnhyUS/D2bQ9tMYjEE6Ub\nj00b7zn8LIh/Za/WYfyNAUENt6SxMODA4EPabOBkj0dh+ZTBntRygaq8BFHE6GuM\nY3a/VmxtdWKQcMEG8mpC07lMlHs9xpeHCeZpzsBN3SMOWp6j7/lED/rzbV1RBxSA\nm3mCR4elE0VspPaZTbNh/6wSyB0OhLYVTUy7GGEedXhI0WDDkkRq+VB2fszNFB5Q\np3ZIQqu4197kg8WzAxoSmp/rYkreNUCXmcXprhTZrrgOrdVzWRdP6CXjkO/K/zFe\nZS6rztAjnMyuMv8BRCHkfnthxz4va1kHo6kVRr117tOaBDBaxFmmmC7PKqTRvqXP\nbQIDAQAB\n-----END PUBLIC KEY-----\n
;

const public_adafruit_PEM =
    \\-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAspBrYNk+vSWi8taRt8rW\nFLyg+y5bC4ZA+mIXGd3RLEm0fjXzi90N4iHxM6zwtdEO1dLbuj8KDbpC5rDpEMfx\nMBmvmJVpvbVbZclOUKpNLIKdkPmPFKDCNpNUgGSk+q8IISkaAX6o3bAu9magy6ix\ntNo8UBYa+IkqOJDbehh1C5gf/4REyuuSyYXIqjlWN6AoHBVglDTkxGyIQ2kjFRPh\n1U5Wrlmu2O/vg3GH9zHn++iz5vKnMm9Incr8TqqklCuklNXxb/cICWolWTOILanY\nWlMT3QUOvW7yaJGWe9Ph7z59SqKGTQfnGfMY1F+5LLO0KhjrBDc5DCMy+F4SP2XX\nMwIDAQAB\n-----END PUBLIC KEY-----\n
;
