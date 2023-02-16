const std = @import("std");
const Zigstr = @import("Zigstr");

// http signature
// ? may need the headers sanitized before this point
// ? the 2019 ietf draft specifies ASCII
pub fn verify(al: std.mem.Allocator, headers: std.StringHashMap([]const u8)) []const u8 {
    var map = std.StringHashMap([]const u8).init(al);
    defer map.deinit();
    // 1. extract keyId, header, signature, digest
    // 2. calc checksum

    var input = headers.get("signature") orelse "SIGN.FAIL";

    var str = Zigstr.fromConstBytes(al, input) catch return "SIGN.FAIL";
    defer str.deinit();

    var split_iter = str.splitIter(",");

    //DEBUG
    // look for the pattern ,name="value"
    // may need to trim whitespace
    while (split_iter.next()) |kv| {
        var scratch = Zigstr.fromConstBytes(al, kv) catch return "SIGN.FAIL";
        defer scratch.deinit();

        if (scratch.startsWith("keyId") or
            scratch.startsWith("signature") or
            scratch.startsWith("algorithm") or
            scratch.startsWith("created") or
            scratch.startsWith("expires") or
            scratch.startsWith("headers") or
            scratch.startsWith("digest"))
        {
            var tup = scratch.split(al, "=") catch return "SIGN.FAIL";
            defer al.free(tup);
            map.put(tup[0], tup[1]) catch return "SIGN.FAIL";
        }
    }

    // count of expected pairs
    if (map.contains("keyId") and map.contains("digest")) {
        var value = map.get("keyId");
        if (value) |v| {
            return v;
        }
    }

    return "SIGN.FAIL";
}

const SignatureError = error{
    SignatureKeyId,
    SignatureAbsent,
};
