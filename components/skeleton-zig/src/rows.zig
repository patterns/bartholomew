const std = @import("std");
const log = std.log;
const mem = std.mem;
const Allocator = mem.Allocator;

// Purpose: attempt EnumArray as data structure for KV pairs (headers/params)
// because the StringHashMap seems to be overkill for small sets.
// (EnumMap may fit, need to compare)
// Since the total size of headers is restricted to 8K by servers
// (consensus according to search results), we need to have our
// implementation of headers complain loudly when we reach the max
// in order to decide whether we need to revisit.....

// rows is a collection of entries (think of table/spreadsheets)
pub fn Rows(comptime T: type, comptime D: type) type {
    return struct {
        const Self = @This();
        cells: std.EnumArray(T, D),
        present: std.EnumSet(T),

        pub fn init() Self {
            return Self{
                .cells = std.EnumArray(T, D).initUndefined(),
                .present = std.EnumSet(T).initEmpty(),
            };
        }

        pub fn get(self: Self, ct: T) D {
            // check whether the enum is a set member
            if (self.present.contains(ct)) {
                return self.cells.get(ct);
            }
            // zero fields
            return D.init(ct, "", "");
        }

        pub fn add(self: *Self, opt: anytype) !void {
            const c_type = opt.cell_type;
            var entry = D.init(c_type, "", "");
            entry.update(opt.value, opt.label);

            // include membership in set
            self.present.insert(c_type);
            // insert entry into collection
            self.cells.set(c_type, entry);
        }

        // TODO temporary, need attempt the lex/scan because this naive splitting is fragile
        // unmarshal raw data found within signature subheaders
        pub fn read(self: *Self, raw: []const u8) !void {
            // Since we combine the sub-types together with the header enums
            // we are rewriting 'signature' to 'sub-signature' as quick&dirty, for now.
            // splitting on "=" needs re/consideration

            var arr = try std.BoundedArray(Cell(CellType), 64).init(12);

            // expect field1="val1",field2="val2"
            try split(&arr, raw);

            // traverse and assign cell to row
            while (arr.popOrNull()) |sub_header| {
                const c_type = sub_header.cell_type;
                self.present.insert(c_type);
                self.cells.set(c_type, sub_header);
            }
        }
    };
    // TODO need a check that answers whether _required_ elements are present
}
// cell is one entry in the row
pub fn Cell(comptime T: type) type {
    // TODO a cell-type 'other' can land on 1+ values
    //      (maybe keep a linked-list just for that cell-type)
    //      which would mean a flag "has_siblings" or "can_have_siblings"

    return struct {
        const Self = @This();
        cell_type: T,
        value: []const u8,
        label: []const u8,

        pub fn init(ct: T, val: []const u8, label: []const u8) Self {
            return Self{
                .cell_type = ct,
                .value = val,
                .label = label,
            };
        }

        // helper to shape input
        pub fn update(self: *Self, value: []const u8, field: []const u8) void {
            // cell-type may be initialized earlier
            if (self.cell_type == undefined or self.cell_type == .other) {
                // if not, need to "derive" cell-type from field
                self.cell_type = cellEnum(field);
            }
            const label = fmtLabel(self.cell_type, field);
            self.value = value;
            self.label = label;
        }
    };
}

// possible sub/header types for set membership
pub const CellType = enum {
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

    other,
};

// header cell
pub const Header = Cell(CellType);
// collection of header cells
pub const HeaderList = Rows(CellType, Header);
// signature subheader cell
pub const Subheader = Cell(CellType);
// collection of signature subheaders
pub const SignatureList = Rows(CellType, Subheader);

// can we switch on the union of the two enum types?
fn fmtLabel(ct: CellType, default: []const u8) []const u8 {
    var label: []const u8 = undefined;
    switch (ct) {
        .authorization => label = "authorization",
        .date => label = "date",
        .content_type => label = "content-type",
        .content_length => label = "content-length",
        .signature => label = "signature",
        .digest => label = "digest",
        .sub_headers => label = "headers",
        .sub_key_id => label = "keyId",
        .sub_algorithm => label = "algorithm",
        .sub_signature => label = "signature",

        else => {
            // assume label is less than 128 bytes
            var tmp: [128]u8 = undefined;
            var buf = std.ascii.lowerString(&tmp, default);
            return buf;
        },
    }
    return label;
}

// accept name of cell-type, and return the associated enum
fn cellEnum(field: []const u8) CellType {
    var c_type = CellType.other;

    if (streq("authorization", field)) {
        c_type = CellType.authorization;
    } else if (streq("algorithm", field)) {
        c_type = CellType.sub_algorithm;
    } else if (streq("content-type", field)) {
        c_type = CellType.content_type;
    } else if (streq("content-length", field)) {
        c_type = CellType.content_length;
    } else if (streq("date", field)) {
        c_type = CellType.date;
    } else if (streq("digest", field)) {
        c_type = CellType.digest;
    } else if (streq("headers", field)) {
        c_type = CellType.sub_headers;
    } else if (streq("keyId", field)) {
        c_type = CellType.sub_key_id;
    } else if (streq("signature", field)) {
        c_type = CellType.signature;
    } else if (streq("sub-signature", field)) {
        c_type = CellType.sub_signature;
    }

    return c_type;
}
fn streq(comptime text: []const u8, field: []const u8) bool {
    return mem.eql(u8, text, field);
}

fn split(arr: *std.BoundedArray(Cell(CellType), 64), data: []const u8) !void {
    const delim: []const u8 = ",";
    // expect field1=val1<delim>field2=val2

    if (!mem.containsAtLeast(u8, data, 1, delim)) {
        // possible one/single pair
        const tup = try tokens(data);
        var cell: Cell(CellType) = undefined;
        cell.update(tup.value, tup.field);
        try arr.append(cell);
        return;
    }

    var iter = mem.split(u8, data, delim);
    while (iter.next()) |segment| {
        const tup = try tokens(segment);
        var cell: Cell(CellType) = undefined;
        cell.update(tup.value, tup.field);
        try arr.append(cell);
    }
}

// accept 'field1="val1"' and return {field1, val1}
fn tokens(remain: []const u8) !struct { field: []const u8, value: []const u8 } {
    var fld_name: []const u8 = undefined;
    var fld_val: []const u8 = undefined;

    // tokenize stream by equal (=) and quotes (")
    var iter = mem.tokenize(u8, remain, "=\"");

    if (iter.next()) |field| {
        fld_name = field;
    } else {
        log.err("Failed on tokenize field, {s}", .{remain});
        return error.TokenSignatureField;
    }
    if (iter.next()) |value| {
        fld_val = value;
    } else {
        log.err("Failed on tokenize value, {s}", .{remain});
        return error.TokenSignatureValue;
    }

    return .{ .field = fld_name, .value = fld_val };
}

const expectStr = std.testing.expectEqualStrings;

test "headers assignment and retrieval" {
    var headers = HeaderList.init();
    try headers.add(.{ .cell_type = .host, .label = "host", .value = "example.com" });
    try headers.add(.{ .cell_type = .date, .label = "date", .value = "Sun, 05 Jan 2014 21:31:40 GMT" });
    try headers.add(.{ .cell_type = .content_type, .label = "content-type", .value = "application/json" });
    try headers.add(.{ .cell_type = .digest, .label = "digest", .value = "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=" });
    try headers.add(.{ .cell_type = .content_length, .label = "content-length", .value = "18" });
    try headers.add(.{
        .cell_type = .signature,
        .label = "signature",
        .value = "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"",
    });
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
    const sig_rcvd = headers.get(.signature).value;
    try expectStr(
        "keyId=\"Test\",algorithm=\"rsa-sha256\",headers=\"(request-target) host date\",signature=\"qdx+H7PHHDZgy4y/Ahn9Tny9V3GP6YgBPyUXMmoxWtLbHpUnXS2mg2+SbrQDMCJypxBLSPQR2aAjn7ndmw2iicw3HMbe8VfEdKFYRqzic+efkb3nndiv/x1xSHDJWeSWkx3ButlYSuBskLu6kd9Fswtemr3lgdDEmn04swr2Os0=\"",
        sig_rcvd,
    );
}
