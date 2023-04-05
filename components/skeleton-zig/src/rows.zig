const std = @import("std");
const log = std.log;
const mem = std.mem;
const streq = std.ascii.eqlIgnoreCase;

// Purpose: attempt KV pairs (headers/params)
// (keep the header input text alongside the index/offset and size
// values needed to locate their positions within the input text;
// this would let us retain the original headers unaltered while
// avoiding any new allocations). SO MANY rethinks; the xmap that
// we wrote to translate headers from the host was already using the
// StringHashMap. So we need to refactor there which is at the source
// where we first access the input data for the headers.
// thinking (20230404), make xmap a secondary option and write a new
// default xlist using ArrayList/SegmentedList with the assumption that
// the initial translation from host interop/C will be faster and more
// space efficient; this list is then "never" modified but instead
// tapped for the data in some wrapping key-lookup "cache" that is
// the interface to readers.
// Since the total size of headers is restricted to 8K by servers
// (consensus according to search results), we need to have our
// implementation of headers complain loudly when we reach the max
// in order to decide whether we need to revisit.....

// wrapper around raw headers SegmentedList
pub const HeaderList = Rows();
// wrapper around raw subheaders SegmentedList
pub const SignatureList = Rows();
// shorthand for raw headers SegmentedList
pub const SourceHeaders = std.SegmentedList([2][]const u8, 32);

// rows provides convenience routines over the (raw) headers
pub fn Rows() type {
    return struct {
        const Self = @This();
        cells: std.EnumArray(CellType, Cell),
        source: []const u8,

        pub fn init() Self {
            return Self{
                .cells = std.EnumArray(CellType, Cell).initUndefined(),
                .source = "",
            };
        }
        pub fn deinit(self: *Self) void {
            var it = self.cells.iterator();
            while (it.next()) |cell| {
                self.cells.remove(cell.key);
            }
        }

        pub fn get(self: Self, ct: CellType) Cell {
            // check whether the enum is a set member
            const c = self.cells.get(ct);
            if (c.kind == undefined) {
                // zero fields
                return Cell.init(ct, "");
            }

            // TODO look up offset by using enum to key into cells map
            //      then the cell has the offset and size which
            //      tell the position of the field within the source
            //      array.
            //return self.cells.get(ct);
            return c;
        }

        // extract signature subheaders
        pub fn preverify(self: *Self, raw: SourceHeaders) !void {
            // find the signature (cavage draft12)
            var root: []const u8 = undefined;
            var it = raw.constIterator(0);
            while (it.next()) |hd| {
                const tup = hd.*;
                if (streq("signature", tup[0])) {
                    root = tup[1];
                    break;
                }
            }
            std.debug.assert(root.len != 0);
            //if (root == undefined) @panic("Missing signature header (maybe diff spec)");
            self.source = root;

            // TODO scan the text and map the offsets
            //
            var arr = try std.BoundedArray(Cell, 64).init(12);
            // expect field1="val1",field2="val2"
            try scanCommas(&arr, root);
            // traverse and assign cell to row
            while (arr.popOrNull()) |sub_header| {
                const c_type = sub_header.kind;
                self.cells.set(c_type, sub_header);
            }
        }

        // (headers) abstraction layer around SegmentedList
        pub fn index(self: *Self, source: SourceHeaders) void {
            var it = source.constIterator(0);
            while (it.next()) |header| {
                const tup = header.*;
                const c_type = CellType.atoCell(tup[0]);
                var cell = Cell.init(c_type, tup[1]);
                self.cells.set(c_type, cell);
            }
        }
    };
    // TODO need a check that answers whether _required_ elements are present
}

// cell is one entry in the row
pub const Cell = struct {
    // TODO a cell-type 'other' can land on 1+ values
    //      (maybe keep a linked-list just for that cell-type)
    //      which would mean a flag "has_siblings" or "can_have_siblings"

    const Self = @This();
    kind: CellType,
    value: []const u8,

    pub fn init(ct: CellType, value: []const u8) Self {
        return Self{
            .kind = ct,
            .value = value,
        };
    }

    // helper to shape input
    pub fn update(self: *Self, value: []const u8, field: []const u8) void {
        // cell-type may be initialized earlier
        if (self.kind == undefined or self.kind == .other) {
            // if not, need to "derive" cell-type from field
            self.kind = CellType.atoCell(field);
        }

        // TODO verify that we are mem.copy correctly
        self.value = value;
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
    other,

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
        "other",
    };

    // name/label format of the enum type
    pub fn name(self: CellType) [:0]const u8 {
        return CellNameTable[@enumToInt(self)];
    }

    // convert to enum type
    pub fn atoCell(lookup: []const u8) CellType {
        for (CellNameTable, 0..) |row, index| {
            if (streq(row, lookup)) {
                return @intToEnum(CellType, index);
            }
        }
        return .other;
    }
};

fn scanCommas(arr: *std.BoundedArray(Cell, 64), data: []const u8) !void {
    // expect field1=val1<delim>field2=val2
    // tokenize stream by comma (,)
    var iter = mem.tokenize(u8, data, ",");

    var field: [128:0]u8 = undefined;
    var value: [1024:0]u8 = undefined;

    while (iter.next()) |segment| {
        field = mem.zeroes([128:0]u8);
        value = mem.zeroes([1024:0]u8);
        try extractField(segment, &field, &value);
        var cell: Cell = undefined;
        cell.update(&value, &field);
        try arr.append(cell);
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
test "wrapper around raw headers SegmentedList" {
    // simulate raw header values
    var list = SourceHeaders{};
    try list.append(ally, [2][]const u8{ "host", "example.com" });
    try list.append(ally, [2][]const u8{ "date", "Sun, 05 Jan 2014 21:31:40 GMT" });
    try list.append(ally, [2][]const u8{ "content-type", "application/json" });
    try list.append(ally, [2][]const u8{ "digest", "SHA-256=X48E9qOokqqrvdts8nOJRJN3OWDUoyWxBf7kbu9DBPE=" });
    try list.append(ally, [2][]const u8{ "content-length", "18" });

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
