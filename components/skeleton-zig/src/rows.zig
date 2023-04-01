const std = @import("std");
const log = std.log;
const mem = std.mem;
const Allocator = std.mem.Allocator;

// Purpose: attempt EnumArray as data structure for KV pairs (headers/params)
// because the StringHashMap seems to be overkill for small sets.
// (EnumMap may fit, need to compare)

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
            return self.cells.get(ct);
        }

        pub fn add(self: *Self, opt: anytype) !void {
            const c_type = opt.cell_type;
            var label = try fmtLabel(c_type, opt.label);
            var entry: D = undefined;
            entry.set(c_type, opt.val, label);

            // include membership in set
            self.present.insert(c_type);
            // insert entry into collection
            self.cells.set(c_type, entry);
        }

        // unmarshal raw data from the signature subheaders
        pub fn read(self: *Self, raw: []const u8) !void {
            // splitting on "=" needs re/consideration

            // expect field1="val1",field2="val2"
            var list = try split(raw);

            // assign result to rowdata
            while (list.popOrNull()) |sub_header| {
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

    return struct {
        const Self = @This();
        cell_type: T,
        value: []const u8,
        label: []const u8,

        pub fn set(self: *Self, ct: T, val: []const u8, label: []const u8) void {
            self.cell_type = ct;
            self.value = val;
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
fn fmtLabel(ct: CellType, default: []const u8) ![]const u8 {
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
fn cellEnum(name: []const u8) CellType {
    var c_type = CellType.other;

    if (mem.eql(u8, "authorization", name)) {
        c_type = CellType.authorization;
    } else if (mem.eql(u8, "algorithm", name)) {
        c_type = CellType.sub_algorithm;
    } else if (mem.eql(u8, "content-type", name)) {
        c_type = CellType.content_type;
    } else if (mem.eql(u8, "content-length", name)) {
        c_type = CellType.content_length;
    } else if (mem.eql(u8, "date", name)) {
        c_type = CellType.date;
    } else if (mem.eql(u8, "digest", name)) {
        c_type = CellType.digest;
    } else if (mem.eql(u8, "headers", name)) {
        c_type = CellType.sub_headers;
    } else if (mem.eql(u8, "keyId", name)) {
        c_type = CellType.sub_key_id;
    } else if (mem.eql(u8, "signature", name)) {
        c_type = CellType.signature;
    } else if (mem.eql(u8, "sub-signature", name)) {
        c_type = CellType.sub_signature;
    }

    return c_type;
}

// TODO instead of ba, is there a more minimal list that is good for insert+purge
fn split(data: []const u8) !std.BoundedArray(Cell(CellType), 64) {
    const delim: []const u8 = ",";
    // expect field1=val1<delim>field2=val2

    // intermediate buffer
    var arr = try std.BoundedArray(Cell(CellType), 64).init(2);

    if (!mem.containsAtLeast(u8, data, 1, delim)) {
        // possible one/single pair
        const tmp = pairs(data);
        if (tmp) |pair| {
            const c_type = cellEnum(pair[0]);
            var label = try fmtLabel(c_type, pair[0]);
            var cell: Cell(CellType) = undefined;
            cell.set(c_type, pair[1], label);
            try arr.append(cell);
        }
        return arr;
    }

    var iter = mem.split(u8, data, delim);
    while (iter.next()) |segment| {
        const tmp = pairs(segment);
        if (tmp) |pair| {
            const c_type = cellEnum(pair[0]);
            var label = try fmtLabel(c_type, pair[0]);
            var cell: Cell(CellType) = undefined;
            cell.set(c_type, pair[1], label);
            try arr.append(cell);
        } else {
            log.warn("unexpected param format: {s}", .{segment});
            break;
        }
    }
    return arr;
}

// accept 'field1=val1' and return {field1, val1}
fn pairs(remain: []const u8) ?[2][]const u8 {
    const sz = remain.len;
    var div: usize = undefined;
    if (mem.indexOf(u8, remain, "=")) |index| {
        div = index;
    } else {
        return null;
    }
    const fld = remain[0..div];
    const val = remain[(div + 1)..sz];

    const discard: []const u8 = "\"";
    var cleaned = mem.trim(u8, val, discard);

    var pair = [2][]const u8{ fld, cleaned };
    return pair;
}
