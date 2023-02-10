const std = @import("std");
const Zigstr = @import("Zigstr");
const sign = @import("../signature.zig");
const expect = std.testing.expect;

test "verify requires keyId" {
    const al = std.testing.allocator;
    const check = verify(al, "");
    try expect(@TypeOf(check) == SignatureError);
}
