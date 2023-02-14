const std = @import("std");
const sdk = @cImport({
    @cInclude("stddef.h");
    @cInclude("spin-http.h");
});

// purpose - adapter to encapsulate sdk-aware types
//           and decouple downstream logic that needs the headers
//           (look at the github.com/jedisc1/zigly fastly edge api)

const Headers = struct {
    map: std.StringHashMap([]const u8),

    pub fn init(
        self: Headers,
        al: std.mem.Allocator,
        req: *sdk.spin_http_request_t,
        ) void {
        self.map = pairs(al, req);
    }
};

fn pairs(al: std.mem.Allocator, req: *sdk.spin_http_request_t) std.StringHashMap([]const u8) {
    // notes - not meant as general headers container and
    //         only want specific items (Signature, Content-Type, Digest)
    // TODO encapsulate map to handle deinit and release k/v items
    //      (need to track clist in order to free later)
    const clist: sdk.spin_http_headers_t = req.headers;
    const sz = clist.len;
    const many: [*c]sdk.spin_http_tuple2_string_string_t = clist.ptr;

    var hm = std.StringHashMap([]const u8).init(al);
    for (many[0..sz]) |tuple| {
        const key: []const u8 = std.mem.span(tuple.f0.ptr);
        const val: []const u8 = std.mem.span(tuple.f1.ptr);

        ////if (eq("signature", key) or eq("content-type", key)) {
        hm.put(key, val) catch std.debug.print("FAIL HashMap, {s}", .{key});
        ////}
    }

    return hm;
}


