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
    var vkey = try vfr.produceVerifier(ally);
    defer vkey.deinit();

    // modulus as string
    const modtxt = try vkey.n.toString(ally, 10, std.fmt.Case.upper);
    try expectStr("136287014989608765893123126038106572662775969591951227130418898610855192325348933630885960405684877794822018571580683189422700394681986953780776002189134127788826182440724839043317920353954669979929011493094302864518238564874305630519223810399534512757200334611583365920204719997149421452315257365248562982089", modtxt);

    // TODO expected exponent '65537' (ask for help?)
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
    var vkey = try vfr.produceVerifier(ally);
    defer vkey.deinit();

    // modulus as string
    const modtxt = try vkey.n.toString(ally, 10, std.fmt.Case.upper);
    try expectStr("19959745154717260766510463162970710631663779706865741160613921920435198377669499241147026536329436882612052228253583784306606573942618214251040679639065815859836226591094607170357852600947616568746275862413065385149717970244738004652546695884680785830372485548560800434022650933424341378162731829435201718727230410102380634535995195109526898585440535352317797613836457677131435531780171344963088904510086645739642769505138649692114641475287574785612115032442996390738542433212013867772270704780375477017383131473008970986931683136509333049977699126195960445604467573205716311271669820991682802880620492258712505143149", modtxt);
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
    var vkey = try vfr.produceVerifier(ally);
    defer vkey.deinit();

    // modulus as string
    const modtxt = try vkey.n.toString(ally, 10, std.fmt.Case.upper);
    try expectStr("22541634167300894830429877870905611113467892885325984703149971271335901157143961493096015008757236032148800349683239880541366618454668309123463357922693759993591987075346602073283379840223082159701545870699227513706551658115102046155398425663840779422599828982407108664307549899675381358628510413453975750624683116301398804174698302368992447502014840264611043031502373275172644048673501733726274629021449854038511149615792732543199503156216765007897587697069326937541198241807010358067180969750501119690587482393731216630646107288897166496790769431037525531451238923734209354350547835555926330207550730576901133686579", modtxt);
}

////    return error.SkipZigTest;

////const test_key_rsa_pss = @embedFile("test-key-rsa-pss.pem");
fn produceFromPublicKeyPEM(proxy: []const u8, ally: std.mem.Allocator) !std.crypto.Certificate.rsa.PublicKey {
    // skip network trip that would normally connect to proxy/provider
    _ = proxy;
    var fbs = std.io.fixedBufferStream(public_key_PEM);
    return vfr.fromPEM(fbs.reader(), ally);
}
fn produceFromEFFPEM(proxy: []const u8, ally: std.mem.Allocator) !std.crypto.Certificate.rsa.PublicKey {
    // skip network trip that would normally connect to proxy/provider
    _ = proxy;
    var fbs = std.io.fixedBufferStream(public_eff_PEM);
    return vfr.fromPEM(fbs.reader(), ally);
}
fn produceFromAdafruitPEM(proxy: []const u8, ally: std.mem.Allocator) !std.crypto.Certificate.rsa.PublicKey {
    // skip network trip that would normally connect to proxy/provider
    _ = proxy;
    var fbs = std.io.fixedBufferStream(public_adafruit_PEM);
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
