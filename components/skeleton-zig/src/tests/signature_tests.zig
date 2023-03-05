const std = @import("std");

const lib = @import("../lib.zig");
const sig = @import("../signature.zig");
const Allocator = std.mem.Allocator;
const ed25519 = std.crypto.sign.Ed25519;
const expect = std.testing.expect;
const expectErr = std.testing.expectError;
const expectStr = std.testing.expectEqualStrings;
const debug = std.debug;

fn helloRSA(allocator: Allocator) void {
    //const check = try sig.verifyPKCS1v15(allocator,
    //    );
}

test "calculate rsa compatible" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var allocator = arena.allocator();
    var req = try requestHelloRSA(allocator);

    helloRSA(allocator);
    const result = try sig.calculate(
        allocator,
        .{
            .public = true,
            .key = publicKeyHelloRSA,
            .request = req,
        },
    );
    try expectStr("", result);
}

test "calculate ed25519 compatible" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const req = try requestEd25519(allocator);

    const result = try sig.calculate(
        allocator,
        .{
            .public = true,
            .key = publicKeyEd25519,
            .request = req,
        },
    );
    try expectStr("", result);
}

test "verify requires signature" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var req = requestNoSignature(allocator);

    const result = sig.calculate(
        allocator,
        .{
            .public = true,
            .key = publicKeyHelloRSA,
            .request = req,
        },
    );
    try expectErr(sig.SignatureError.SignatureAbsent, result);
}

// TODO
//const pubrsa_pem = @embedFile("pubrsa.pem");
//const prvrsa_pem = @embedFile("prvrsa.pem");
fn publicKeyHelloRSA(proxy: []const u8) []const u8 {
    _ = proxy;
    return "PUBKEY-TEST";
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

const cert_pem =
    \\-----BEGIN CERTIFICATE-----
    \\MIIB1zCCAX2gAwIBAgIUd15IMhkhVtUY+I6IKaX6/AfKxTowCgYIKoZIzj0EAwIw
    \\QTELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBUt5b3RvMQ4wDAYDVQQHDAVLeW90bzES
    \\MBAGA1UEAwwJbG9jYWxob3N0MB4XDTIyMTAyNDA3MjgyMVoXDTIzMTAyNDA3Mjgy
    \\MVowQTELMAkGA1UEBhMCSlAxDjAMBgNVBAgMBUt5b3RvMQ4wDAYDVQQHDAVLeW90
    \\bzESMBAGA1UEAwwJbG9jYWxob3N0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE
    \\idRm6Es+u4v1Ng/nArk7F7u+lkzG1tpKbdcsHGJ9I9iRXWkN18r26eajCF/UaHhy
    \\fuhGonTQT76OYEBDFOVgL6NTMFEwHQYDVR0OBBYEFAgmoQ1rUK+z9B+pzkJbdAXT
    \\Is3dMB8GA1UdIwQYMBaAFAgmoQ1rUK+z9B+pzkJbdAXTIs3dMA8GA1UdEwEB/wQF
    \\MAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIgcR+087vas0CVyG0jGHAXSWTebGIeCDbg
    \\dwZ12GwlZv0CIQC8/6Qe512S97xnN+Mm2UkBoy1bu6dn5MUkjMhe2QDdxw==
    \\-----END CERTIFICATE-----
;

const chain_pem =
    \\
    \\# Hellenic Academic and Research Institutions RootCA 2011
    \\-----BEGIN CERTIFICATE-----
    \\MIIEMTCCAxmgAwIBAgIBADANBgkqhkiG9w0BAQUFADCBlTELMAkGA1UEBhMCR1Ix
    \\RDBCBgNVBAoTO0hlbGxlbmljIEFjYWRlbWljIGFuZCBSZXNlYXJjaCBJbnN0aXR1
    \\dGlvbnMgQ2VydC4gQXV0aG9yaXR5MUAwPgYDVQQDEzdIZWxsZW5pYyBBY2FkZW1p
    \\YyBhbmQgUmVzZWFyY2ggSW5zdGl0dXRpb25zIFJvb3RDQSAyMDExMB4XDTExMTIw
    \\NjEzNDk1MloXDTMxMTIwMTEzNDk1MlowgZUxCzAJBgNVBAYTAkdSMUQwQgYDVQQK
    \\EztIZWxsZW5pYyBBY2FkZW1pYyBhbmQgUmVzZWFyY2ggSW5zdGl0dXRpb25zIENl
    \\cnQuIEF1dGhvcml0eTFAMD4GA1UEAxM3SGVsbGVuaWMgQWNhZGVtaWMgYW5kIFJl
    \\c2VhcmNoIEluc3RpdHV0aW9ucyBSb290Q0EgMjAxMTCCASIwDQYJKoZIhvcNAQEB
    \\BQADggEPADCCAQoCggEBAKlTAOMupvaO+mDYLZU++CwqVE7NuYRhlFhPjz2L5EPz
    \\dYmNUeTDN9KKiE15HrcS3UN4SoqS5tdI1Q+kOilENbgH9mgdVc04UfCMJDGFr4PJ
    \\fel3r+0ae50X+bOdOFAPplp5kYCvN66m0zH7tSYJnTxa71HFK9+WXesyHgLacEns
    \\bgzImjeN9/E2YEsmLIKe0HjzDQ9jpFEw4fkrJxIH2Oq9GGKYsFk3fb7u8yBRQlqD
    \\75O6aRXxYp2fmTmCobd0LovUxQt7L/DICto9eQqakxylKHJzkUOap9FNhYS5qXSP
    \\FEDH3N6sQWRstBmbAmNtJGSPRLIl6s5ddAxjMlyNh+UCAwEAAaOBiTCBhjAPBgNV
    \\HRMBAf8EBTADAQH/MAsGA1UdDwQEAwIBBjAdBgNVHQ4EFgQUppFC/RNhSiOeCKQp
    \\5dgTBCPuQSUwRwYDVR0eBEAwPqA8MAWCAy5ncjAFggMuZXUwBoIELmVkdTAGggQu
    \\b3JnMAWBAy5ncjAFgQMuZXUwBoEELmVkdTAGgQQub3JnMA0GCSqGSIb3DQEBBQUA
    \\A4IBAQAf73lB4XtuP7KMhjdCSk4cNx6NZrokgclPEg8hwAOXhiVtXdMiKahsog2p
    \\6z0GW5k6x8zDmjR/qw7IThzh+uTczQ2+vyT+bOdrwg3IBp5OjWEopmr95fZi6hg8
    \\TqBTnbI6nOulnJEWtk2C4AwFSKls9cz4y51JtPACpf1wA+2KIaWuE4ZJwzNzvoc7
    \\dIsXRSZMFpGD/md9zU1jZ/rzAxKWeAaNsWftjj++n08C9bMJL/NMh98qy5V8Acys
    \\Nnq/onN694/BtZqhFLKPM58N7yLcZnuEvUUXBj08yrl3NI/K6s8/MT7jiOOASSXI
    \\l7WdmplNsDz4SgCbZN2fOUvRJ9e4
    \\-----END CERTIFICATE-----
    \\
    \\# ePKI Root Certification Authority
    \\-----BEGIN CERTIFICATE-----
    \\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
    \\hNQ+IIX3Sj0rnP0qCglN6oH4EZw=
    \\-----END CERTIFICATE-----
;
