const std = @import("std");
const str = @import("strings.zig");
const Allocator = std.mem.Allocator;
const log = std.log;

// TODO ?outbound http need to be enabled per destination
//      which may make it impossible to allow every possible site of the public PEM key
//      (maybe we want to make a proxy that handles the trip to these destinations)
//      so use a configuration setting to allow toggling.

pub fn calculate(allocator: Allocator, option: anytype) ![]const u8 {
    const req = option.request;
    const hdr = req.headers;

    var raw: []const u8 = undefined;
    if (hdr.get("signature")) |sig| {
        raw = sig;
    } else {
        log.err("httpsig signature is required", .{});
        return error.SignatureAbsent;
    }
    var pairs = str.sigPairs(allocator, raw);
    defer pairs.deinit();

    var seq: []const u8 = undefined;
    if (pairs.get("headers")) |place| {
        seq = place;
    } else {
        log.err("httpsig sequence is required", .{});
        return error.SignatureSequence;
    }
    var iter = std.mem.split(u8, seq, " ");
    var input_string = std.ArrayList(u8).init(allocator);
    defer input_string.deinit();
    const writer = input_string.writer();

    // construct input-string according to 'headers'
    const first = iter.first();
    try formatInputLeader(&input_string, first, req.method, req.uri);

    while (iter.next()) |field| {
        if (str.eq("host", field)) {
            if (hdr.get("host")) |name| {
                try writer.print("\nhost: {s}", .{name});
            } else {
                log.err("httpsig host is required\n", .{});
                return error.SignatureHost;
            }
        } else if (str.eq("date", field)) {
            //todo check timestamp
            if (hdr.get("date")) |date| {
                try writer.print("\ndate: {s}", .{date});
            } else {
                log.err("httpsig date is required\n", .{});
                return error.SignatureDate;
            }
        } else if (str.eq("digest", field)) {
            //todo check digest
            if (hdr.get("digest")) |digest| {
                try writer.print("\ndigest: {s}", .{digest});
            } else {
                log.err("httpsig digest is required\n", .{});
                return error.SignatureDigest;
            }
        } else {
            const val = hdr.get(field) orelse "00000";
            try writer.print("\n{s}: {s}", .{ field, val });
        }
    }
    //TODO
    // _minimum_ required elements are date, host, and digest (method != get)
    // it's an hard error when any are missing.

    const sha = std.crypto.hash.sha2.Sha256;
    var buf: [32]u8 = std.mem.zeroes([32]u8);
    sha.hash(input_string.items, &buf, sha.Options{});
    log.debug("sha, {any}\n", .{buf});

    log.debug("httpsig verify flow, {any}\n", .{option.public});
    var proxy: []const u8 = undefined;
    if (pairs.get("keyId")) |svc| {
        proxy = svc;
    } else {
        log.err("httpsig keyId is required\n", .{});
        return error.SignatureKeyId;
    }
    const key = option.key;
    const pubkey = key(proxy);
    log.debug("key, {any}\n", .{pubkey});
    //std.crypto.ecdsa.Signature.verify(buf, pubkey);

    log.debug("sig input, {s}\n", .{input_string.items});
    //todo allocate if need
    return "PLACEHOLDER";
}

// "algorithm") or
// "created") or
// "expires") or

fn formatInputLeader(
    inpstr: *std.ArrayList(u8),
    first: []const u8,
    method: u8,
    uri: []const u8,
) !void {
    if (!std.mem.startsWith(u8, first, "(request-target)")) {
        // input sequence always starts with
        log.err("sig hdr unkown format, \n", .{});
        return error.SignatureFormat;
    }

    const verb = fmtMethod(method);
    var writer = inpstr.*.writer();
    try writer.print("{0s}: {1s} {2s}", .{ first, verb, uri });
}

fn fmtMethod(m: u8) []const u8 {
    switch (m) {
        0 => return "get",
        1 => return "post",
        2 => return "put",
        3 => return "delete",
        4 => return "patch",
        5 => return "head",
        6 => return "options",
        else => unreachable,
    }
}

const SignatureError = error{
    SignatureKeyId,
    SignatureAbsent,
    SignatureSequence,
    SignatureFormat,
    SignatureHost,
    SignatureDate,
    SignatureDigest,
};
