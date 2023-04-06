const std = @import("std");
const log = std.log;
const mem = std.mem;
const streq = std.ascii.eqlIgnoreCase;

// Purpose: attempt KV pairs (headers/params)

// Since the total size of headers is restricted to 8K by servers
// (consensus according to search results), we need to have our
// implementation of headers complain loudly when we reach the max
// in order to decide whether we need to revisit.....

// wrapper around raw headers
pub const HeaderList = Rows();
// wrapper around raw subheaders
pub const SignatureList = Rows();
// shorthand for raw headers
pub const SourceHeaders = std.MultiArrayList(struct {
    field: [:0]const u8,
    value: [:0]const u8,
});

// convenience layer around (raw) headers
pub fn Rows() type {
    return struct {
        const Self = @This();
        cells: std.EnumArray(CellType, Header),
        source: SourceHeaders,

        pub fn init() Self {
            return Self{
                .cells = std.EnumArray(CellType, Header).initUndefined(),
                .source = undefined,
            };
        }
        pub fn deinit(self: *Self) void {
            var it = self.cells.iterator();
            while (it.next()) |cell| {
                self.cells.remove(cell.key);
            }
        }

        pub fn get(self: Self, ct: CellType) struct {
            kind: CellType,
            value: []const u8,
            descr: []const u8,
        } {
            const hdr = self.cells.get(ct);
            // check whether the enum is a set member
            if (hdr.kind == undefined) {
                // zero fields
                return .{ .kind = ct, .value = "", .descr = "" };
            }
            var val: []const u8 = undefined;
            var fld: []const u8 = undefined;
            switch (ct) {
                .sub_algorithm, .sub_headers, .sub_key_id, .sub_signature => {
                    // access subheaders by slice
                    const root = self.signatureEntry();
                    std.debug.assert(root.len != 0);
                    const v_len = hdr.val_pos + hdr.val_len;
                    const f_len = hdr.fld_pos + hdr.fld_len;
                    val = root[hdr.val_pos..v_len];
                    fld = root[hdr.fld_pos..f_len];
                },

                else => {
                    // access headers by index of mal
                    const tup = self.source.get(hdr.fld_pos);
                    val = tup.value;
                    fld = tup.field;
                },
            }
            return .{ .kind = ct, .value = val, .descr = fld };
        }

        // extract signature subheaders
        pub fn preverify(self: *Self, raw: SourceHeaders) !void {
            self.source = raw;
            //const src = self.source;
            //var root: []const u8 = undefined;
            //for (src.items(.field), src.items(.value)) |field, value| {
            //    if (streq("signature", field)) {
            // found signature (cavage draft12)
            //        root = value;
            //        break;
            //    }
            //}
            const root = self.signatureEntry();
            std.debug.assert(root.len != 0);
            //if (root == undefined) @panic("Missing signature header (maybe diff spec)");

            var arr = try std.BoundedArray(Header, 64).init(12);
            // expect field1="val1",field2="val2"
            try scanCommas(&arr, root);
            while (arr.popOrNull()) |sub_hdr| {
                self.cells.set(sub_hdr.kind, sub_hdr);
            }
        }

        // sort raw headers into structured data
        pub fn index(self: *Self, raw: SourceHeaders) void {
            self.source = raw;
            const src = self.source;
            for (src.items(.field), src.items(.value), 0..) |field, value, rownum| {
                const kind = CellType.atoMember(field);
                self.cells.set(kind, Header{
                    .kind = kind,
                    .fld_pos = rownum,
                    .fld_len = field.len,
                    .val_pos = rownum,
                    .val_len = value.len,
                });
            }
        }

        // retrieve the signature from raw headers
        fn signatureEntry(self: Self) []const u8 {
            const src = self.source;
            var root: []const u8 = undefined;
            for (src.items(.field), src.items(.value)) |field, value| {
                if (streq("signature", field)) {
                    // found signature (cavage draft12)
                    root = value;
                    break;
                }
            }
            return root;
        }
    };
    // TODO need a check that answers whether _required_ elements are present
}

// header entry
pub const Header = struct {
    kind: CellType,
    //value: []const u8,
    //description: []const u8,
    fld_pos: usize,
    fld_len: usize,
    val_pos: usize,
    val_len: usize,

    // TODO helper to shape input
    pub fn update(self: *Header, field: []const u8) void {
        // cell-type may be initialized earlier
        if (self.kind == undefined or self.kind == .user_defined) {
            // if not, need to "derive" cell-type from field
            self.kind = CellType.atoMember(field);
        }

        // TODO verify that we are mem.copy correctly
        //self.value = value;
        //self.description = field;
    }
};

// sub/header set members
pub const CellType = enum(u32) {
    authorization,
    content_type,
    content_length,
    date,
    digest,
    host,
    signature,
    sub_algorithm,
    sub_headers,
    sub_key_id,
    sub_signature,
    user_defined,
    // TODO member type user_defined can land on 1+ values
    //      (maybe keep a linked-list just for that member type)
    //      which would mean a flag "has_siblings" or "can_have_siblings"

    // lookup table with the name/label
    pub const CellNameTable = [@typeInfo(CellType).Enum.fields.len][:0]const u8{
        "authorization",
        "content-type",
        "content-length",
        "date",
        "digest",
        "host",
        "signature",
        "algorithm",
        "headers",
        "keyid",
        "SUB-SIGNATURE",
        "user-defined",
    };

    // name/label format of the enum
    pub fn name(self: CellType) [:0]const u8 {
        return CellNameTable[@enumToInt(self)];
    }

    // convert to enum
    pub fn atoMember(lookup: []const u8) CellType {
        for (CellNameTable, 0..) |row, index| {
            if (streq(row, lookup)) {
                return @intToEnum(CellType, index);
            }
        }
        return .user_defined;
    }
};

fn scanCommas(arr: *std.BoundedArray(Header, 64), root: []const u8) !void {
    // expect field1=val1<delim>field2=val2

    var iter = mem.tokenize(u8, root, ",");
    var pos: usize = 0;

    while (iter.next()) |segment| {
        //const delim_eq = mem.indexOf(u8, segment, "=");
        if (mem.indexOf(u8, segment, "=")) |delim| {
            const f_start = pos;
            const f_len = delim - pos;
            const v_start = delim + 1;
            const v_len = segment.len - delim - 1;
            const field = segment[f_start..(f_start + f_len)];
            const kind = CellType.atoMember(field);

            var hd = Header{
                .kind = kind,
                .fld_pos = f_start,
                .fld_len = f_len,
                .val_pos = v_start,
                .val_len = v_len,
            };
            try arr.append(hd);
            pos = pos + segment.len + 1;
        } else {
            break;
        }
    }
}

// accept 'field1="val1"' and return {field1, val1}
fn extractField(remain: []const u8, field: []u8, value: []u8) !void {
    // this has to be the culprit, there are equal signs inside the sub-signature!
    // tokenize stream by equal (=)
    ////var iter = mem.tokenize(u8, remain, "=");

    var stream = std.io.fixedBufferStream(remain);
    var reader = stream.reader();
    var tmp_fld: [128:0]u8 = undefined;
    var tmp_val: [1024:0]u8 = undefined;

    // read field-name
    var tmpn = try reader.readUntilDelimiter(&tmp_fld, '=');
    log.info("subheader name, {s}", .{tmpn});

    // expect open quotation marks
    var open_quotes = try reader.readByte();
    //TODO verify open quotation marks (and log.err if not)
    log.info("subheader value starts (open quotes), {c}", .{open_quotes});

    // read field-value
    var tmpv = try reader.readUntilDelimiter(&tmp_val, '"');
    log.info("subheader value, {s}", .{tmpv});

    // copy the field-name into result
    mem.copy(u8, field, &tmp_fld);
    // copy the field-value into result
    mem.copy(u8, value, &tmp_val);
}

const expectStr = std.testing.expectEqualStrings;
const ally = std.testing.allocator;
test "wrapper around raw headers " {
    // simulate raw header values
    var list = SourceHeaders{};
    try list.append(ally, .{ .field = "host", .value = "example.com" });
    try list.append(ally, .{ .field = "date", .value = "Sun, 05 Jan 2014 21:31:40 GMT" });
    try list.append(ally, .{ .field = "content-type", .value = "application/json" });
    try list.append(ally, .{ .field = "digest", .value = "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=" });
    try list.append(ally, .{ .field = "content-length", .value = "18" });

    // headers wrapper around SegmentedList
    var headers = HeaderList.init();
    headers.index(list);

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
