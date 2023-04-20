const std = @import("std");
const log = std.log;
const mem = std.mem;
const streq = std.ascii.eqlIgnoreCase;

// Purpose: attempt pairs (headers/params)

// Since the total size of headers is restricted to 8K by servers
// (consensus according to search results), we need to have our
// implementation of headers complain loudly when we reach the max
// in order to decide whether we need to revisit.....

// wrapper around raw headers
pub const HeaderList = Params();
// wrapper around raw auth-params (descendant values from signature header)
pub const AuthParams = Params();
// TODO shorthand for raw headers
pub const RawHeaders = [128]RawField;
pub const RawField = struct {
    fld: []const u8,
    val: []const u8,
};

// convenience layer around raw headers
pub fn Params() type {
    return struct {
        const Self = @This();
        source: RawHeaders,
        cells: std.AutoHashMap(Kind, Header),

        pub fn init(ally: std.mem.Allocator, raw: RawHeaders) Self {
            return Self{
                .source = raw,
                .cells = std.AutoHashMap(Kind, Header).init(ally),
            };
        }
        pub fn deinit(self: *Self) void {
            self.cells.deinit();
            //    var it = self.cells.iterator();
            //    while (it.next()) |cell| {

            //    }
        }

        pub fn get(self: Self, ct: Kind) struct {
            kind: Kind,
            value: []const u8,
            descr: []const u8,
        } {
            // check whether the enum is a set member
            if (!self.cells.contains(ct)) {
                // zero fields
                return .{ .kind = ct, .value = "", .descr = "" };
            }
            const hdr = self.cells.get(ct).?;

            var val: []const u8 = undefined;
            var fld: []const u8 = undefined;
            switch (ct) {
                .sub_algorithm, .sub_headers, .sub_key_id, .sub_signature => {
                    // access subheaders by slice
                    const root = self.rawSignature();
                    std.debug.assert(root.len != 0);
                    const v_len = hdr.val_pos + hdr.val_len;
                    const f_len = hdr.fld_pos + hdr.fld_len;
                    val = root[hdr.val_pos..v_len];
                    fld = root[hdr.fld_pos..f_len];
                },

                else => {
                    // access headers by index
                    const tup = self.source[hdr.fld_pos];
                    val = tup.val[0..];
                    fld = tup.fld[0..];
                },
            }
            return .{ .kind = ct, .value = val, .descr = fld };
        }

        // extract signature subheader fields
        pub fn preverify(self: *Self) !void {
            const root = self.rawSignature();
            std.debug.assert(root.len != 0);

            // TODO should be segmentedList? (better append/pop)
            var arr = try std.BoundedArray(Header, 64).init(12);

            try draft12Fields(&arr, root);
            while (arr.popOrNull()) |entry| {
                try self.cells.put(entry.kind, entry);
            }
        }

        // sort raw headers into indexed list
        pub fn catalog(self: *Self) !void {
            var rownum: usize = 0;
            while (rownum < self.source.len) : (rownum += 1) {
                const tup = self.source[rownum];
                if (tup.fld.len == 0) break;

                const kind = Kind.fromDescr(tup.fld);
                try self.cells.put(kind, Header{
                    .kind = kind,
                    .fld_pos = rownum,
                    .fld_len = tup.fld.len,
                    .val_pos = rownum,
                    .val_len = tup.val.len,
                });
            }
        }

        // retrieve the signature from raw headers
        fn rawSignature(self: Self) []const u8 {
            var rownum: usize = 0;
            while (rownum < self.source.len) : (rownum += 1) {
                const tup = self.source[rownum];
                if (tup.fld.len == 0) break;

                if (streq("signature", tup.fld[0..])) {
                    return tup.val[0..];
                }
            }
            return "";
        }
    };
    // TODO need a check that answers whether _required_ elements are present
}

// header entry
pub const Header = packed struct {
    kind: Kind,
    fld_pos: usize,
    fld_len: usize,
    val_pos: usize,
    val_len: usize,
};

// sub/header set membership
pub const Kind = enum(u8) {
    www_authenticate,
    authorization,
    proxy_authenticate,
    proxy_authorization,
    age,
    cache_control,
    clear_site_data,
    expires,
    pragma,
    warning,
    downlink,
    ect,
    rtt,
    last_modified,
    etag,
    if_match,
    if_none_match,
    if_modified_since,
    if_unmodified_since,
    vary,
    connection,
    keep_alive,
    accept,
    accept_encoding,
    accept_language,
    expect,
    max_forwards,
    cookie,
    set_cookie,
    content_encoding,
    content_type,
    content_length,
    content_language,
    content_location,
    forwarded,
    via,
    from,
    referer,
    referrer_policy,
    user_agent,
    allow,
    server,
    date,
    digest,
    host,
    signature,
    sub_algorithm,
    sub_headers,
    sub_key_id,
    sub_signature,
    sub_created,
    sub_expires,
    user_defined,
    // TODO member type user_defined can land on 1+ values
    //      (maybe keep a linked-list just for that member type)
    //      which would mean a flag "has_siblings" or "can_have_siblings"

    // convert to enum
    pub fn fromDescr(text: []const u8) Kind {
        if (streq("www-authenticate", text)) return .www_authenticate;
        if (streq("authorization", text)) return .authorization;
        if (streq("proxy-authenticate", text)) return .proxy_authenticate;
        if (streq("proxy-authorization", text)) return .proxy_authorization;
        if (streq("age", text)) return .age;
        if (streq("cache-control", text)) return .cache_control;
        if (streq("clear-site-data", text)) return .clear_site_data;
        if (streq("expires", text)) return .expires;
        if (streq("pragma", text)) return .pragma;
        if (streq("warning", text)) return .warning;
        if (streq("downlink", text)) return .downlink;
        if (streq("ect", text)) return .ect;
        if (streq("rtt", text)) return .rtt;
        if (streq("last-modified", text)) return .last_modified;
        if (streq("etag", text)) return .etag;
        if (streq("if-match", text)) return .if_match;
        if (streq("if-none-match", text)) return .if_none_match;
        if (streq("if-modified-since", text)) return .if_modified_since;
        if (streq("if-unmodified-since", text)) return .if_unmodified_since;
        if (streq("vary", text)) return .vary;
        if (streq("connection", text)) return .connection;
        if (streq("keep-alive", text)) return .keep_alive;
        if (streq("accept", text)) return .accept;
        if (streq("accept-encoding", text)) return .accept_encoding;
        if (streq("accept-language", text)) return .accept_language;
        if (streq("expect", text)) return .expect;
        if (streq("max-forwards", text)) return .max_forwards;
        if (streq("cookie", text)) return .cookie;
        if (streq("set-cookie", text)) return .set_cookie;
        if (streq("content-encoding", text)) return .content_encoding;
        if (streq("content-type", text)) return .content_type;
        if (streq("content-length", text)) return .content_length;
        if (streq("content-language", text)) return .content_language;
        if (streq("content-location", text)) return .content_location;
        if (streq("forwarded", text)) return .forwarded;
        if (streq("via", text)) return .via;
        if (streq("from", text)) return .from;
        if (streq("referer", text)) return .referer;
        if (streq("referrer-policy", text)) return .referrer_policy;
        if (streq("user-agent", text)) return .user_agent;
        if (streq("allow", text)) return .allow;
        if (streq("server", text)) return .server;
        if (streq("date", text)) return .date;
        if (streq("digest", text)) return .digest;
        if (streq("host", text)) return .host;
        if (streq("signature", text)) return .signature;
        if (streq("algorithm", text)) return .sub_algorithm;
        if (streq("headers", text)) return .sub_headers;
        if (streq("keyid", text)) return .sub_key_id;
        if (streq("created", text)) return .sub_created;
        if (streq("expires", text)) return .sub_expires;
        if (streq("SUB-SIGNATURE", text)) return .sub_signature;

        // "USER-DEFINED"
        return .user_defined;
    }

    //const DescrTable = [@typeInfo(Kind).Enum.fields.len][:0]const u8{
    // description (name) format of the enum
    //fn toDescr(self: Kind) [:0]const u8 {
    // using the term description because meaning of name is more specific
    // and we need a overloaded/fuzzier definition of the text representation
    //    return DescrTable[@enumToInt(self)];
    //}
    //fn fromDescr(text: []const u8) Kind {
    //    for (DescrTable, 0..) |row, rownum| {
    //        if (streq(row, text)) {
    //            return @intToEnum(Kind, rownum);
    //        }
    //    }
    //    return .user_defined;
    //}
};

// accept the signature subheader, return list containing offsets to fields
fn draft12Fields(arr: *std.BoundedArray(Header, 64), root: []const u8) !void {
    var start_index: usize = 0;

    // expect 'segment1<delim-comma>segment2'
    while (mem.indexOfPos(u8, root, start_index, ",")) |mark| {
        // mark is the segment end position
        try subheaderOffsets(arr, root, start_index, mark);
        // next segment starts
        start_index = mark + 1;
    }
    std.debug.assert(start_index != 0);
    // possibility that only one segment so comma was not present
    // (except can a valid signature only have one field, not really)

    // calc last field, where terminator comma would be end of string
    const end_mark = root.len;
    try subheaderOffsets(arr, root, start_index, end_mark);
}

// calculate the offsets of a field within the signature
fn subheaderOffsets(
    arr: *std.BoundedArray(Header, 64),
    root: []const u8,
    start_index: usize,
    mark: usize,
) !void {
    const f_start = start_index;
    const pos = mem.indexOfPos(u8, root, start_index, "=");
    if (pos == null) return error.SignatureFieldFormat;
    // pos separates field and value
    const f_len = pos.? - start_index;
    const v_start = pos.? + 1;
    const v_len = mark - v_start;

    var lookup = root[f_start..(f_start + f_len)];
    if (streq("signature", lookup)) {
        // work-around enum collision
        lookup = "SUB-SIGNATURE";
    }
    const kind = Kind.fromDescr(lookup);
    var hd = Header{
        .kind = kind,
        .fld_pos = f_start,
        .fld_len = f_len,
        .val_pos = v_start,
        .val_len = v_len,
    };
    try arr.append(hd);
}

const expectStr = std.testing.expectEqualStrings;

test "wrapper around raw headers " {
    const ally = std.testing.allocator;
    // simulate raw header values
    var raw: RawHeaders = undefined;

    raw[0] = RawField{ .fld = "host", .val = "example.com" };
    raw[1] = RawField{ .fld = "date", .val = "Sun, 05 Jan 2014 21:31:40 GMT" };
    raw[2] = RawField{ .fld = "content-type", .val = "application/json" };
    raw[3] = RawField{ .fld = "digest", .val = "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=" };
    raw[4] = RawField{ .fld = "content-length", .val = "18" };

    // wrap raw headers
    var headers = HeaderList.init(ally, raw);
    defer headers.deinit();
    try headers.catalog();

    // assignment and retrieval checks
    const host_rcvd = headers.get(.host).value;
    try expectStr("example.com", host_rcvd);
    const date_rcvd = headers.get(.date).value;
    try expectStr("Sun, 05 Jan 2014 21:31:40 GMT", date_rcvd);
    const digest_rcvd = headers.get(.digest).value;
    try expectStr("SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=", digest_rcvd);
    const contenttype_rcvd = headers.get(.content_type).value;
    try expectStr("application/json", contenttype_rcvd);
    const contentlen_rcvd = headers.get(.content_length).value;
    try expectStr("18", contentlen_rcvd);
}

test "extraction of signature subheaders" {
    const ally = std.testing.allocator;
    // simulate raw header values
    var raw: RawHeaders = undefined;

    raw[0] = RawField{
        .fld = "signature",
        .val = "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"",
    };

    // wrap subheaders
    var subheaders = AuthParams.init(ally, raw);
    defer subheaders.deinit();
    try subheaders.preverify();

    const sh_keyid = subheaders.get(.sub_key_id).value;
    try expectStr("\"Test\"", sh_keyid);
    const sh_algo = subheaders.get(.sub_algorithm).value;
    try expectStr("\"rsa-sha256\"", sh_algo);
    const sh_hd = subheaders.get(.sub_headers).value;
    try expectStr("\"(request-target) host date\"", sh_hd);

    const sh_sig = subheaders.get(.sub_signature).value;
    try expectStr("\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"", sh_sig);

    // is this extra decode step unecessary (because we don't need to unit test stdlib's base64)
    const cleaned = std.mem.trim(u8, sh_sig, "\"");
    var b64 = std.base64.standard.Decoder;
    var decoded_orig: [256]u8 = undefined;
    var decoded_sub: [256]u8 = undefined;

    try b64.decode(
        &decoded_orig,
        "qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=",
    );
    try b64.decode(&decoded_sub, cleaned);

    try std.testing.expectEqual(decoded_orig, decoded_sub);
}
