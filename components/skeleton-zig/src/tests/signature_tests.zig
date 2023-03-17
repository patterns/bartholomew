const std = @import("std");

const lib = @import("../lib.zig");
const signature = @import("../signature.zig");
const Allocator = std.mem.Allocator;
const ed25519 = std.crypto.sign.Ed25519;
const expect = std.testing.expect;
const expectErr = std.testing.expectError;
const expectStr = std.testing.expectEqualStrings;
const debug = std.debug;

////test "minimal signature (TODO using rsa-pss-sha512)" {
test "example signature " {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var allocator = arena.allocator();
    var req = try testRequest(allocator);
    signature.init(allocator, .{ .request = req });
    defer signature.deinit();
    signature.attachFetch(testKeyRSAPSS);
    const hashed = try signature.calculate(allocator, .{ .request = req });
    const check = try signature.verify(allocator, hashed);

    try expect(check);
}

test "verify can read rsa public key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var allocator = arena.allocator();

    return error.SkipZigTest;
    var req = try requestHelloRSA(allocator);
    signature.init(allocator, .{ .request = req });
    defer signature.deinit();
    signature.attachFetch(publicKeyHelloRSA);
    const hashed = try signature.calculate(allocator, .{ .request = req });
    const check = try signature.verify(allocator, hashed);
    debug.print("test {any}", .{check});

    try expect(check);
}

test "calculate ed25519 compatible" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const req = try requestEd25519(allocator);
    debug.print("TBD {any}", .{req.method});
    //try expectStr("", "PLACEHOLDER");
    return error.SkipZigTest;
}

test "verify requires signature" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var req = requestNoSignature(allocator);

    debug.print("TBD {any}", .{req.method});
    //try expectErr(signature.SignatureError.SignatureAbsent,
    //    signature.SignatureError.FetchNotDefined);
    return error.SkipZigTest;
}

//const test_key_rsa_pss = @embedFile("test-key-rsa-pss.pem");
fn testKeyRSAPSS(allocator: Allocator, proxy: []const u8) signature.PublicKey {
    _ = proxy;
    const key = signature.fromPEM(allocator, pub_key_pem) catch |err| {
        debug.panic("PEM decode failed, {!}", .{err});
    };

    return signature.PublicKey{
        .N = key.N,
        .E = key.E,
    };
}

fn publicKeyHelloRSA(allocator: Allocator, proxy: []const u8) signature.PublicKey {
    _ = proxy;

    const key = signature.fromPEM(allocator, pubPEM) catch |err| {
        debug.panic("PEM decode failed, {!}", .{err});
    };

    return signature.PublicKey{
        .N = key.N,
        .E = key.E,
    };
}
fn publicKeyEd25519(proxy: []const u8) []const u8 {
    _ = proxy;
    return "PUBKEY-TEST";
}

fn testRequest(allocator: Allocator) !*lib.HttpRequest {
    var headers = std.StringHashMap([]const u8).init(allocator);
    var params = std.StringHashMap([]const u8).init(allocator);
    var body = std.ArrayList(u8).init(allocator);

    const post = 1;
    const uri = "/foo?param=value&pet=dog";

    try body.appendSlice("{\"hello\": \"world\"}");
    try headers.put("host", "example.com");
    try headers.put("date", "Thu, 05 Jan 2014 21:31:40 GMT");
    try headers.put("content-type", "application/json");
    try headers.put("digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
    try headers.put("content-length", "18");
    try headers.put(
        "signature",
        "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"\"",
    );
    return newRequest(allocator, post, uri, headers, params, body);
}
fn requestHelloRSA(allocator: Allocator) !*lib.HttpRequest {
    var headers = std.StringHashMap([]const u8).init(allocator);
    var params = std.StringHashMap([]const u8).init(allocator);
    var body = std.ArrayList(u8).init(allocator);

    const post = 1;
    const uri = "/foo?param=value&pet=dog";

    try body.appendSlice("{\"hello\": \"world\"}");
    try headers.put("host", "example.com");
    try headers.put("date", "Thu, 05 Jan 2014 21:31:40 GMT");
    try headers.put("content-type", "application/json");
    try headers.put("digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=");
    try headers.put("content-length", "18");
    try headers.put(
        "signature",
        "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date content-type digest content-length\",signature=\"Ef7MlxLXoBovhil3AlyjtBwAL9g4TN3tibLj7uuNB3CROat/9KaeQ4hW2NiJ+pZ6HQEOx9vYZAyi+7cmIkmJszJCut5kQLAwuX+Ms/mUFvpKlSo9StS2bMXDBNjOh4Auj774GFj4gwjS+3NhFeoqyr/MuN6HsEnkvn6zdgfE2i0=\"",
    );
    return newRequest(allocator, post, uri, headers, params, body);
}

fn requestEd25519(allocator: Allocator) !*lib.HttpRequest {
    var headers = std.StringHashMap([]const u8).init(allocator);
    var params = std.StringHashMap([]const u8).init(allocator);
    var body = std.ArrayList(u8).init(allocator);

    const post = 1;
    const uri = "/foo?param=value&pet=dog";

    try body.appendSlice("{\"hello\": \"ed25519\"}");
    try headers.put(
        "signature",
        "",
    );
    return newRequest(allocator, post, uri, headers, params, body);
}

fn requestNoSignature(allocator: Allocator) *lib.HttpRequest {
    var headers = std.StringHashMap([]const u8).init(allocator);
    var params = std.StringHashMap([]const u8).init(allocator);
    var body = std.ArrayList(u8).init(allocator);

    const post = 1;
    const uri = "/foo?param=value&pet=dog";

    return newRequest(allocator, post, uri, headers, params, body);
}

fn newRequest(
    allocator: Allocator,
    method: u8,
    uri: []const u8,
    headers: std.StringHashMap([]const u8),
    params: std.StringHashMap([]const u8),
    body: std.ArrayList(u8),
) *lib.HttpRequest {
    var req = lib.HttpRequest{
        .allocator = allocator,
        .method = method,
        .uri = uri,
        .headers = headers,
        .params = params,
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
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt0c14FLZWHqgNJzlHrpR
    \\yx9CuW+w5DYo/5s59FZHEgNzTjUJyE3Jfxx1j/6gcCWmZGoTULR5ILZySe/jagQw
    \\JvLl7dkOcf7K3FGh3JpoTeZpInFjVSyKag3PfstQI/Hq/JIV9mysGk2hNoo/0Jvh
    \\2vT48jGuxhrwHchJdNeYs8eBtvSfIlXsnt9K1qZVU9T+anG7wwn42t5GcQ391vxk
    \\DLgUzF5K1wSzOQoXh5lryW/BZzEmAhFqGZz69UsjRoS1ia53nb1LjXBpZdetvqU6
    \\0YlOHfRc19tgUnmkMqXqMV6lRUmFqyFh/kj50GE5FsuQSjlNaKiotuZg/KJ/DhfO
    \\HwIDAQAB
    \\-----END PUBLIC KEY-----
;

// TODO try more examples from the draft
// (https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-message-signatures-16)

