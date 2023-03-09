const std = @import("std");

const lib = @import("../lib.zig");
const signature = @import("../signature.zig");
const Allocator = std.mem.Allocator;
const ed25519 = std.crypto.sign.Ed25519;
const expect = std.testing.expect;
const expectErr = std.testing.expectError;
const expectStr = std.testing.expectEqualStrings;
const debug = std.debug;

test "verify can read rsa public key" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var allocator = arena.allocator();
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

//const prvrsa_pem = @embedFile("prvrsa.pem");
//const pubrsa_pem = @embedFile("pubrsa.pem");
fn publicKeyHelloRSA(allocator: Allocator, proxy: []const u8) signature.PublicKey {
    _ = proxy;
    //const key = signature.fromPEM(allocator, pubrsa_pem) catch {
    const key = signature.fromPEM(allocator, pubPEM) catch {
        debug.panic("PEM decode failed", .{});
    };

    debug.print("N E: {any}, {any}", .{ key.N, key.E });
    return key;
}
fn publicKeyEd25519(proxy: []const u8) []const u8 {
    _ = proxy;
    return "PUBKEY-TEST";
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
