const std = @import("std");

const lib = @import("../lib.zig");
const vfr = @import("../verifier.zig");
const phi = @import("../phi.zig");
const proof = @import("../modules/rsa/proof.zig");
const expect = std.testing.expect;
const expectErr = std.testing.expectError;
const expectStr = std.testing.expectEqualStrings;
const cert = std.crypto.Certificate;
const fmt = std.fmt;
const log = std.log;
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
    _ = try fmt.hexToBytes(&minsum, "f29e22e3a108abc999f5b0ed27cdb461ca30cdbd3057efa170af52c83dfc0ca6");

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
    _ = try fmt.hexToBytes(&regsum, "53CD4050FF72E3A6383091186168F3DF4CA2E6B3A77CBED60A02BA00C9CD8078");

    // With the headers specified, our signature base must be sum:
    try std.testing.expectEqual(regsum, base[0..32].*);
}

// obtaining the verifier key usually requires a network trip so we make the step
// accept a "harvest" function which is the purpose of this test
test "produce verifier rsa" {
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
    var pv = try vfr.produceVerifier(ally);
    defer pv.deinit(ally);
    var scratch_buf: [512]u8 = undefined;

    // read key's octet string (answers whether our PEM harvester did ok)
    const pk_components = try cert.rsa.PublicKey.parseDer(pv.bits());

    // base-16: 65536 4096 256 16 1
    // which makes 65537 into 0x010001
    var txt_exponent: []u8 = try fmt.bufPrint(&scratch_buf, "{any}", .{fmt.fmtSliceHexLower(pk_components.exponent)});
    try expectStr("010001", txt_exponent);

    var txt_modulus: []u8 = try fmt.bufPrint(&scratch_buf, "{any}", .{fmt.fmtSliceHexUpper(pk_components.modulus)});
    try expectStr("C2144346C37DF21A2872F76A438D94219740B7EAB3C98FE0AF7D20BCFAADBC871035EB5405354775DF0B824D472AD10776AAC05EFF6845C9CD83089260D21D4BEFCFBA67850C47B10E7297DD504F477F79BF86CF85511E39B8125E0CAD474851C3F1B1CA0FA92FF053C67C94E8B5CFB6C63270A188BED61AA9D5F21E91AC6CC9", txt_modulus);
}

test "produce verifier eff" {
    // TODO clean up memory leak
    //const ally = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();

    // minimal headers
    var raw = minRawHeaders();
    // fake public key via our custom harvester
    try vfr.init(ally, raw);
    vfr.attachFetch(produceFromEFFPEM);
    var pv = try vfr.produceVerifier(ally);
    defer pv.deinit(ally);
    var scratch_buf: [512]u8 = undefined;
    // read key bitstring
    const pk_components = try cert.rsa.PublicKey.parseDer(pv.bits());

    var txt_exponent: []u8 = try fmt.bufPrint(&scratch_buf, "{any}", .{fmt.fmtSliceHexLower(pk_components.exponent)});
    try expectStr("010001", txt_exponent);

    var txt_modulus: []u8 = try fmt.bufPrint(&scratch_buf, "{any}", .{fmt.fmtSliceHexUpper(pk_components.modulus)});
    try expectStr("9E1C944BF0F66D0F6D3188C413A51B8F4D1BEF39FC2C887F65AFD661FC8D01410DB7A4B130E0C0E043DA6CE0648F4761F994C19ED47281AABC0451C4E86B8C6376BF566C6D75629070C106F26A42D3B94C947B3DC6978709E669CEC04DDD230E5A9EA3EFF9440FFAF36D5D510714809B79824787A513456CA4F6994DB361FFAC12C81D0E84B6154D4CBB18611E757848D160C392446AF950767ECCCD141E50A7764842ABB8D7DEE483C5B3031A129A9FEB624ADE35409799C5E9AE14D9AEB80EADD57359174FE825E390EFCAFF315E652EABCED0239CCCAE32FF014421E47E7B61C73E2F6B5907A3A91546BD75EED39A04305AC459A6982ECF2AA4D1BEA5CF6D", txt_modulus);
}
test "produce verifier adafruit" {
    // TODO clean up memory leak
    //const ally = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();

    // minimal headers
    var raw = minRawHeaders();
    // fake public key via our custom harvester
    try vfr.init(ally, raw);
    vfr.attachFetch(produceFromAdafruitPEM);
    var pv = try vfr.produceVerifier(ally);
    defer pv.deinit(ally);
    var scratch_buf: [512]u8 = undefined;
    // read key bitstring
    const pk_components = try cert.rsa.PublicKey.parseDer(pv.bits());

    var txt_exponent: []u8 = try fmt.bufPrint(&scratch_buf, "{any}", .{fmt.fmtSliceHexLower(pk_components.exponent)});
    try expectStr("010001", txt_exponent);

    var txt_modulus: []u8 = try fmt.bufPrint(&scratch_buf, "{any}", .{fmt.fmtSliceHexUpper(pk_components.modulus)});
    try expectStr("B2906B60D93EBD25A2F2D691B7CAD614BCA0FB2E5B0B8640FA621719DDD12C49B47E35F38BDD0DE221F133ACF0B5D10ED5D2DBBA3F0A0DBA42E6B0E910C7F13019AF989569BDB55B65C94E50AA4D2C829D90F98F14A0C23693548064A4FAAF0821291A017EA8DDB02EF666A0CBA8B1B4DA3C50161AF8892A3890DB7A18750B981FFF8444CAEB92C985C8AA395637A0281C15609434E4C46C884369231513E1D54E56AE59AED8EFEF837187F731E7FBE8B3E6F2A7326F489DCAFC4EAAA4942BA494D5F16FF708096A255933882DA9D85A5313DD050EBD6EF26891967BD3E1EF3E7D4AA2864D07E719F318D45FB92CB3B42A18EB0437390C2332F85E123F65D733", txt_modulus);
}

test "verifyRsa as public module" {
    // TODO clean up memory leak
    //const ally = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const ally = arena.allocator();

    // sim rcv request
    var rcv = lib.SpinRequest{
        .ally = ally,
        .method = @enumToInt(vfr.Verb.post),
        .uri = "/inbox",
        .params = undefined,
        .headers = honkRawHeaders(),
        .body = undefined,
    };
    // wrap raw headers
    var wrap = phi.HeaderList.init(ally, rcv.headers);
    try wrap.catalog();
    // honk public key
    try vfr.init(ally, rcv.headers);
    vfr.attachFetch(produceFromHonkPEM);
    const base = try vfr.fmtBase(rcv, wrap);

    const result = try vfr.bySigner(ally, base);
    try expect(result == true);
}
////return error.SkipZigTest;

fn produceFromPublicKeyPEM(ally: std.mem.Allocator, proxy: []const u8) !vfr.ParsedVerifier {
    // skip network trip that would normally connect to proxy/provider
    _ = proxy;
    var fbs = std.io.fixedBufferStream(public_key_PEM);
    return vfr.fromPEM(ally, fbs.reader());
}
fn produceFromEFFPEM(ally: std.mem.Allocator, proxy: []const u8) !vfr.ParsedVerifier {
    // skip network trip that would normally connect to proxy/provider
    _ = proxy;
    var fbs = std.io.fixedBufferStream(public_eff_PEM);
    return vfr.fromPEM(ally, fbs.reader());
}
fn produceFromAdafruitPEM(ally: std.mem.Allocator, proxy: []const u8) !vfr.ParsedVerifier {
    // skip network trip that would normally connect to proxy/provider
    _ = proxy;
    var fbs = std.io.fixedBufferStream(public_adafruit_PEM);
    return vfr.fromPEM(ally, fbs.reader());
}
fn produceFromHonkPEM(ally: std.mem.Allocator, proxy: []const u8) !vfr.ParsedVerifier {
    // skip network trip that would normally connect to proxy/provider
    _ = proxy;
    var fbs = std.io.fixedBufferStream(public_honk_PEM);
    return vfr.fromPEM(ally, fbs.reader());
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

// accept event header fields
fn honkRawHeaders() phi.RawHeaders {
    var list: phi.RawHeaders = undefined;
    list[0] = phi.RawField{ .fld = "host", .val = "cloud-start-rkqucga6.fermyon.app" };
    list[1] = phi.RawField{ .fld = "date", .val = "Mon, 13 Mar 2023 05:42:45 GMT" };
    list[2] = phi.RawField{ .fld = "content-type", .val = "application/ld+json" };
    list[3] = phi.RawField{ .fld = "digest", .val = "SHA-256=RwHPmgmFFXw+r9NqKuEAeysISvs3eW7BUW/bCvZ41ig=" };
    list[4] = phi.RawField{ .fld = "content-length", .val = "580" };
    list[5] = phi.RawField{
        .fld = "signature",
        .val = "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) date host content-type digest\",signature=\"eMs2giWWQyJNyoSK0PaUGzcdV2JqVM0Se1PMbmOaL/kQF1mtPhxhkkonONpZK9EnYw6yglmQZYbSfOVz1r0/ThSuNYDvLv8zoCa2EkscYIRVZ4F4kBdf4DdtkqH+svj3Mn9haIRdmALTAGsJzPn5EUoblofhgdW1CWOySEPuHueDEV9+kTpHC6o6wwnioKwSHG4/U5ZO9xdvFuU0b0nh4NE9n/pSiilktnsQGFh/AVK3MAlR1P4fQtTN6TRu6WjazoGCPSAa3Yu30FwKVICXyL909UkfAeCEZerT9zluSEteXsUgjFZdGkcfizhMsU0rkmasDHXPrNJaznkqB3kXfg==\"",
    };

    return list;
}

var public_key_PEM =
    \\-----BEGIN PUBLIC KEY-----
    \\MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDCFENGw33yGihy92pDjZQhl0C3
    \\6rPJj+CvfSC8+q28hxA161QFNUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6
    \\Z4UMR7EOcpfdUE9Hf3m/hs+FUR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJw
    \\oYi+1hqp1fIekaxsyQIDAQAB
    \\-----END PUBLIC KEY-----
;

const public_eff_PEM =
    \\-----BEGIN PUBLIC KEY-----
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnhyUS/D2bQ9tMYjEE6Ub
    \\j00b7zn8LIh/Za/WYfyNAUENt6SxMODA4EPabOBkj0dh+ZTBntRygaq8BFHE6GuM
    \\Y3a/VmxtdWKQcMEG8mpC07lMlHs9xpeHCeZpzsBN3SMOWp6j7/lED/rzbV1RBxSA
    \\m3mCR4elE0VspPaZTbNh/6wSyB0OhLYVTUy7GGEedXhI0WDDkkRq+VB2fszNFB5Q
    \\p3ZIQqu4197kg8WzAxoSmp/rYkreNUCXmcXprhTZrrgOrdVzWRdP6CXjkO/K/zFe
    \\ZS6rztAjnMyuMv8BRCHkfnthxz4va1kHo6kVRr117tOaBDBaxFmmmC7PKqTRvqXP
    \\bQIDAQAB
    \\-----END PUBLIC KEY-----
;

const public_adafruit_PEM =
    \\-----BEGIN PUBLIC KEY-----
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAspBrYNk+vSWi8taRt8rW
    \\FLyg+y5bC4ZA+mIXGd3RLEm0fjXzi90N4iHxM6zwtdEO1dLbuj8KDbpC5rDpEMfx
    \\MBmvmJVpvbVbZclOUKpNLIKdkPmPFKDCNpNUgGSk+q8IISkaAX6o3bAu9magy6ix
    \\tNo8UBYa+IkqOJDbehh1C5gf/4REyuuSyYXIqjlWN6AoHBVglDTkxGyIQ2kjFRPh
    \\1U5Wrlmu2O/vg3GH9zHn++iz5vKnMm9Incr8TqqklCuklNXxb/cICWolWTOILanY
    \\WlMT3QUOvW7yaJGWe9Ph7z59SqKGTQfnGfMY1F+5LLO0KhjrBDc5DCMy+F4SP2XX
    \\MwIDAQAB
    \\-----END PUBLIC KEY-----
;

const public_honk_PEM =
    \\-----BEGIN PUBLIC KEY-----
    \\MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAwLuWyHHpoS/vL/sobSrb
    \\M5sShW23GnSg1EDIUAq7AyY/quVR6vpv8wuEZ9/WGjvGdc9idEd4q7VJb0kijHdl
    \\gDVcwE9Sd/qM7FaYKy/qiChyIcuWpyYsoOvmy+FfpbujkuiFgn1IF1MVnw9LK6Cb
    \\gMSYcu4AE3IXeM9tcyITDN0apo4ak5Z7Fi/tQkWIoAavLoXzwiA1vOM18aytP0im
    \\ulGkfYQ/aBM4SsLJTT6ZF61y0i3HuX/Z4E+hR4pjKWYnpwv2d1mtASUs1WUZ9WF+
    \\Z2FryGFgH0yf18gDBmDZtLrZCaD061cIk8EHmysM71EKe2CLcdw7UavocfMIWkg0
    \\IwIDAQAB
    \\-----END PUBLIC KEY-----
;
