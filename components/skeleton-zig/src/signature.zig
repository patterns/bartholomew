const std = @import("std");

const Allocator = std.mem.Allocator;
const log = std.log;

// TODO ?outbound http need to be enabled per destination
//      which may make it impossible to allow every possible site of the public PEM key
//      (maybe we want to make a proxy that handles the trip to these destinations)
//      so use a configuration setting to allow toggling.

pub fn calculate(allocator: Allocator, option: anytype) ![]const u8 {
    const public = option.public;
    const req = option.request;
    const hdr = req.headers;

    log.debug("whether need outbound_http, {any}\n", .{public});

    const req_headers = hdr.get("headers") orelse "00000";
    log.debug("sig hdr, {s}\n", .{req_headers});
    var iter = std.mem.split(u8, req_headers, " ");
    const first = iter.first();
    if (!std.mem.eql(u8, "(request-target)", first)) {
        // input order always starts with
        log.err("sig hdr unkown format, \n", .{});

        return error.SignatureFormat;
    }

    // construct input string based on the headers field
    var input_string = std.ArrayList(u8).init(allocator);
    defer input_string.deinit();
    const writer = input_string.writer();
    const method = fmtMethod(req.method);
    try writer.print("{0s}: {1s} {2s}", .{ first, method, req.uri });

    while (iter.next()) |fldname| {
        if (hdr.get(fldname)) |fldval| {
            log.debug("hdr val, {s}\n", .{fldval});
            try writer.print("\n{0s}: {1s}", .{ fldname, fldval });
        } else {
            log.err("sig required hdr, {s}\n", .{fldname});
            return "";
        }
    }

    log.debug("sig input, {s}\n", .{input_string.items});

    const sha = std.crypto.hash.sha2.Sha256;
    var buf: [32]u8 = std.mem.zeroes([32]u8);
    sha.hash(input_string.items, &buf, sha.Options{});
    log.debug("sha, {any}\n", .{buf});

    ////std.crypto.ecdsa.Signature.verify(msg, pubkey);

    return "PLCHOLDER";
}

//        if (scratch.startsWith("keyId") or
//            scratch.startsWith("algorithm") or
//            scratch.startsWith("created") or
//            scratch.startsWith("expires") or

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
    SignatureFormat,
};
