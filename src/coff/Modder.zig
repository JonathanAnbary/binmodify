const std = @import("std");

const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();

const utils = @import("../utils.zig");
const shift_forward = utils.shift_forward;
const ShiftError = utils.ShiftError;
const FileRangeFlags = utils.FileRangeFlags;
const align_ceil = utils.align_ceil;

const Parsed = @import("Parsed.zig");

fn off_lessThanFn(ranges: []FileRange, lhs: RangeIndex, rhs: RangeIndex) bool {
    return lhs.get(ranges.ptr).off < rhs.get(ranges.ptr).off;
}

fn addr_lessThanFn(ranges: []FileRange, lhs: RangeIndex, rhs: RangeIndex) bool {
    return lhs.get(ranges.ptr).addr < rhs.get(ranges.ptr).addr;
}

pub const Error = error{
    AddrNotMapped,
    NoMatchingOffset,
    OffsetNotLoaded,
    NoCaveOption,
    InvalidOptionalHeaderMagic,
    IntersectingFileRanges,
    UnexpectedEof,
    VirtualSizeLessThenFileSize,
    FieldNotAdjustable,
    TooManyFileRanges,
    UnmappedRange,
} || ShiftError || std.io.StreamSource.ReadError || std.io.StreamSource.WriteError || std.io.StreamSource.SeekError || std.io.StreamSource.GetSeekPosError || std.coff.CoffError || std.mem.Allocator.Error;

pub const SecEdge: type = struct {
    sec_idx: RangeIndex,
    is_end: bool,
};

pub const EdgeType = SecEdge;

const SectionHeaderFields = std.meta.FieldEnum(std.coff.SectionHeader);
const CoffHeaderFields = std.meta.FieldEnum(std.coff.CoffHeader);

const Bitness = enum {
    @"32",
    @"64",
};

const PartialHeader = struct {
    bitness: Bitness,
    file_alignment: u32,
    section_alignment: u32,
    image_base: u64,
    coff_header_offset: usize,
    size_of_optional_header: u16,
    size_of_code: u32,
    size_of_image: u32,
    size_of_initialized_data: u32,
    size_of_uninitialized_data: u32,
};

const SectionFlags = packed struct {
    /// The section contains executable code.
    CNT_CODE: u1 = 0,

    /// The section contains initialized data.
    CNT_INITIALIZED_DATA: u1 = 0,

    /// The section contains uninitialized data.
    CNT_UNINITIALIZED_DATA: u1 = 0,
};

const FileRange: type = struct {
    off: u64,
    filesz: u64,
    addr: u64, // TODO: should be nullable
    memsz: u64,
    flags: FileRangeFlags,
    section_flags: SectionFlags,
    to_off: OffIndex,
    to_addr: AddrIndex,
    adjust: u64,
};

const Modder = @This();

const RangeIndex = utils.Index(FileRange);
const OffIndex = utils.Index(RangeIndex);
const AddrIndex = utils.Index(RangeIndex);

header: PartialHeader,
len: u16,
ranges: [*]FileRange, // std.coff.SectionHeader,
off_to_range: [*]RangeIndex,
addr_to_range: [*]RangeIndex,

pub fn init(gpa: std.mem.Allocator, parsed_source: *const Parsed, parse_source: anytype) Error!Modder {
    const coff_header = parsed_source.coff.getCoffHeader();
    const optional_header = parsed_source.coff.getOptionalHeader();
    const image_base = parsed_source.coff.getImageBase();
    const bitness: Bitness = switch (optional_header.magic) {
        std.coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => .@"32",
        std.coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => .@"64",
        else => unreachable, // We assume we have validated the header already
    };
    const size_of_headers = switch (bitness) {
        .@"32" => parsed_source.coff.getOptionalHeader32().size_of_headers,
        .@"64" => parsed_source.coff.getOptionalHeader64().size_of_headers,
    };
    if (coff_header.number_of_sections > std.math.maxInt(u16) - 2) return Error.TooManyFileRanges;
    // + 2 for PE header, and overlay.
    const ranges_count: u16 = coff_header.number_of_sections + 2;
    const ranges = try gpa.alloc(FileRange, ranges_count);
    errdefer gpa.free(ranges);
    ranges[0] = .{
        .addr = 0,
        .filesz = size_of_headers,
        .memsz = @sizeOf(std.coff.CoffHeader) + coff_header.size_of_optional_header + @sizeOf(std.coff.SectionHeader) * coff_header.number_of_sections,
        .flags = .{},
        .section_flags = .{},
        .off = 0,
        .to_off = undefined,
        .to_addr = undefined,
        .adjust = undefined,
    };
    for (parsed_source.coff.getSectionHeaders(), 1..) |sechdr, i| {
        ranges[i] = .{
            .off = sechdr.pointer_to_raw_data,
            .memsz = sechdr.virtual_size,
            .addr = sechdr.virtual_address,
            .filesz = sechdr.size_of_raw_data,
            .flags = .{
                .execute = sechdr.flags.MEM_EXECUTE == 1,
                .read = sechdr.flags.MEM_READ == 1,
                .write = sechdr.flags.MEM_WRITE == 1,
            },
            .section_flags = .{
                .CNT_CODE = sechdr.flags.CNT_CODE,
                .CNT_INITIALIZED_DATA = sechdr.flags.CNT_INITIALIZED_DATA,
                .CNT_UNINITIALIZED_DATA = sechdr.flags.CNT_UNINITIALIZED_DATA,
            },
            .to_off = undefined,
            .to_addr = undefined,
            .adjust = undefined,
        };
    }
    std.debug.print("\n\nnumber_of_sections = {}\n", .{coff_header.number_of_sections});
    const addr_to_range = try gpa.alloc(RangeIndex, ranges_count);
    errdefer gpa.free(addr_to_range);
    const off_to_range = try gpa.alloc(RangeIndex, ranges_count);
    errdefer gpa.free(off_to_range);
    // NOTE: We iterate over ranges_count - 1 since we still have the overlay to add to the ranges array.
    // We reserve a spot at the start of the addr_to_range array since we place the overlay at address zero,
    // and at the end of the off_to_range array since the overlay comes last.
    for (0..ranges_count - 1) |i| {
        addr_to_range[i + 1] = @enumFromInt(i);
        off_to_range[i] = @enumFromInt(i);
    }
    std.sort.pdq(RangeIndex, addr_to_range[1..ranges_count], ranges, off_lessThanFn);
    std.sort.pdq(RangeIndex, off_to_range[0 .. ranges_count - 1], ranges, addr_lessThanFn);
    const end_pos = try parse_source.getEndPos();
    const last_off_range_idx = off_to_range[ranges_count - 2];
    const overlay_off = last_off_range_idx.get(ranges.ptr).off + last_off_range_idx.get(ranges.ptr).filesz;
    const overlay_size = end_pos - overlay_off;
    ranges[ranges_count - 1] = .{
        .addr = 0,
        .filesz = overlay_size,
        .memsz = 0,
        .flags = .{},
        .section_flags = .{},
        .off = overlay_off,
        .to_off = undefined,
        .to_addr = undefined,
        .adjust = undefined,
    };
    off_to_range[ranges_count - 1] = @enumFromInt(ranges_count - 1);
    addr_to_range[0] = @enumFromInt(ranges_count - 1);
    for (off_to_range, addr_to_range, 0..) |off_idx, addr_idx, idx| {
        off_idx.get(ranges.ptr).to_off = @enumFromInt(idx);
        addr_idx.get(ranges.ptr).to_addr = @enumFromInt(idx);
    }

    return Modder{
        .header = .{
            .bitness = bitness,
            .file_alignment = switch (bitness) {
                .@"64" => parsed_source.coff.getOptionalHeader64().file_alignment,
                .@"32" => parsed_source.coff.getOptionalHeader32().file_alignment,
            },
            .section_alignment = switch (bitness) {
                .@"64" => parsed_source.coff.getOptionalHeader64().section_alignment,
                .@"32" => parsed_source.coff.getOptionalHeader32().section_alignment,
            },
            .size_of_image = switch (bitness) {
                .@"64" => parsed_source.coff.getOptionalHeader64().size_of_image,
                .@"32" => parsed_source.coff.getOptionalHeader32().size_of_image,
            },
            .image_base = image_base,
            .coff_header_offset = parsed_source.coff.coff_header_offset,
            .size_of_optional_header = parsed_source.coff.getCoffHeader().size_of_optional_header,
            .size_of_code = parsed_source.coff.getOptionalHeader().size_of_code,
            .size_of_initialized_data = parsed_source.coff.getOptionalHeader().size_of_initialized_data,
            .size_of_uninitialized_data = parsed_source.coff.getOptionalHeader().size_of_uninitialized_data,
        },
        .len = ranges_count,
        .ranges = ranges.ptr,
        .addr_to_range = addr_to_range.ptr,
        .off_to_range = off_to_range.ptr,
    };
}

pub fn deinit(self: *Modder, gpa: std.mem.Allocator) void {
    gpa.free(self.off_to_range[0..self.len]);
    gpa.free(self.addr_to_range[0..self.len]);
    gpa.free(self.ranges[0..self.len]);
}

// Get an identifier for the location within the file where additional data could be inserted.
// TODO: consider if this function should also look at existing gaps to help find the cave which requires the minimal shift.
pub fn get_cave_option(self: *const Modder, wanted_size: u64, flags: FileRangeFlags) Error!?SecEdge {
    var i = self.len;
    while (i > 0) {
        i -= 1;
        const range_idx = self.off_to_range[i];
        if (range_idx.get(self.ranges).flags != flags) continue;
        // NOTE: this assumes you dont have an upper bound on possible memory address.
        const next_range_idx = range_idx.get(self.ranges).to_addr.next().get(self.addr_to_range);
        if ((@intFromEnum(range_idx.get(self.ranges).to_addr) == (self.len - 1)) or
            ((range_idx.get(self.ranges).addr + range_idx.get(self.ranges).memsz + wanted_size) < next_range_idx.get(self.ranges).addr)) return SecEdge{
            .sec_idx = range_idx,
            .is_end = true,
        };
        const addr_idx = range_idx.get(self.ranges).to_addr;
        // NOTE: Im pretty sure the code for section start expansion works but its not currently tested.
        const prev_sec_mem_bound = (if (@intFromEnum(addr_idx) == 0) 0 else (addr_idx.prev().get(self.addr_to_range).get(self.ranges).addr + addr_idx.prev().get(self.addr_to_range).get(self.ranges).memsz));
        const section_aligned_size = align_ceil(u64, wanted_size, self.header.section_alignment);
        if (range_idx.get(self.ranges).addr > (section_aligned_size + prev_sec_mem_bound)) return SecEdge{
            .sec_idx = range_idx,
            .is_end = false,
        };
    }
    return null;
}

fn calc_new_offset(self: *const Modder, index: RangeIndex, size: u64) Error!u64 {
    // TODO: add a check first for the case of an ending edge in which there already exists a large enough gap.
    // and for the case of a start edge whith enough space from the previous segment offset.
    const aligned_size = align_ceil(u64, size, self.header.file_alignment);
    const prev_off_end = blk: {
        const off_idx = index.get(self.ranges).to_off;
        if (@intFromEnum(off_idx) > 0) {
            const temp = off_idx.prev().get(self.off_to_range);
            break :blk temp.get(self.ranges).off + temp.get(self.ranges).filesz;
        } else break :blk 0;
    };
    if (prev_off_end > index.get(self.ranges).off) return Error.IntersectingFileRanges;
    const new_offset = if (index.get(self.ranges).off > (aligned_size + prev_off_end))
        (index.get(self.ranges).off - aligned_size)
    else
        index.get(self.ranges).off;
    return new_offset;
}

fn set_image_file_header_field(self: *const Modder, val: u64, comptime field_name: []const u8, parse_source: anytype) Error!void {
    const offset = self.header.coff_header_offset + @offsetOf(std.coff.CoffHeader, field_name);
    try parse_source.seekTo(offset);
    const T = std.meta.fieldInfo(std.coff.CoffHeader, @field(CoffHeaderFields, field_name)).type;
    const temp: T = @intCast(val);
    const temp2 = std.mem.toBytes(temp);
    if (try parse_source.write(&temp2) != @sizeOf(T)) return Error.UnexpectedEof;
}

fn set_image_optional_header_field(self: *const Modder, val: u64, comptime field_name: []const u8, parse_source: anytype) Error!void {
    if (self.header.bitness == .@"32") {
        const offset = self.header.coff_header_offset + @sizeOf(std.coff.CoffHeader) + @offsetOf(std.coff.OptionalHeaderPE32, field_name);
        try parse_source.seekTo(offset);
        const T = std.meta.fieldInfo(std.coff.OptionalHeaderPE32, @field(std.meta.FieldEnum(std.coff.OptionalHeaderPE32), field_name)).type;
        const temp: T = @intCast(val);
        const temp2 = std.mem.toBytes(temp);
        if (try parse_source.write(&temp2) != @sizeOf(T)) return Error.UnexpectedEof;
    } else {
        const offset = self.header.coff_header_offset + @sizeOf(std.coff.CoffHeader) + @offsetOf(std.coff.OptionalHeaderPE64, field_name);
        try parse_source.seekTo(offset);
        const T = std.meta.fieldInfo(std.coff.OptionalHeaderPE64, @field(std.meta.FieldEnum(std.coff.OptionalHeaderPE64), field_name)).type;
        const temp: T = @intCast(val);
        const temp2 = std.mem.toBytes(temp);
        if (try parse_source.write(&temp2) != @sizeOf(T)) return Error.UnexpectedEof;
    }
}

// NOTE: field changes must NOT change the memory order or offset order!
// TODO: consider what to do when setting the segment which holds the phdrtable itself.
fn set_sechdr_field(self: *const Modder, index: RangeIndex, val: u64, comptime field_name: []const u8, parse_source: anytype) Error!void {
    const secidx = @intFromEnum(index.prev());
    const offset = self.header.coff_header_offset + @sizeOf(std.coff.CoffHeader) + self.header.size_of_optional_header;
    try parse_source.seekTo(offset + @sizeOf(std.coff.SectionHeader) * secidx);
    const T = std.meta.fieldInfo(std.coff.SectionHeader, @field(SectionHeaderFields, field_name)).type;
    const temp: T = @intCast(val);
    try parse_source.seekBy(@offsetOf(std.coff.SectionHeader, field_name));
    const temp2 = std.mem.toBytes(temp);
    if (try parse_source.write(&temp2) != @sizeOf(T)) return Error.UnexpectedEof;
    // @field(self.sechdrs[index], field_name) = @intCast(val);
}

fn set_filerange_field(self: *const Modder, index: RangeIndex, val: u64, comptime field: std.meta.FieldEnum(FileRange), file: anytype) !void {
    switch (self.range_type(index)) {
        .Headers => {
            switch (field) {
                .filesz => try self.set_image_optional_header_field(val, "size_of_headers", file),
                .memsz => {
                    try self.set_image_file_header_field(@divExact(val - @sizeOf(std.coff.CoffHeader) - self.header.size_of_optional_header, @sizeOf(std.coff.SectionHeader)), "number_of_sections", file);
                },
                else => return Error.FieldNotAdjustable,
            }
        },
        .Section => {
            const fieldname = switch (field) {
                .off => "pointer_to_raw_data",
                .addr => "virtual_address",
                .filesz => "size_of_raw_data",
                .memsz => "virtual_size",
                else => return Error.FieldNotAdjustable,
            };
            try self.set_sechdr_field(index, val, fieldname, file);
        },
        .Overlay => {
            switch (field) {
                .off => try self.set_image_file_header_field(val, "pointer_to_symbol_table", file),
                else => return Error.FieldNotAdjustable,
            }
        },
    }
}

const RangeType: type = enum {
    Section,
    Headers,
    Overlay,
};

fn range_type(self: *const Modder, index: RangeIndex) RangeType {
    if (@intFromEnum(index) == 0) return .Headers;
    if (@intFromEnum(index) == (self.len - 1)) return .Overlay;
    return .Section;
}

pub fn create_cave(self: *Modder, size: u32, edge: SecEdge, parse_source: anytype) Error!void {
    const offset = edge.sec_idx.get(self.ranges).off;
    const new_offset: u64 = if (edge.is_end) offset else try self.calc_new_offset(edge.sec_idx, size);
    var needed_size: u32 = @intCast(size + new_offset - offset);

    const first_adjust_off_idx = edge.sec_idx.get(self.ranges).to_off.next();
    var off_idx = first_adjust_off_idx;
    while (@intFromEnum(off_idx) < self.len) : (off_idx = off_idx.next()) {
        const sec_idx = off_idx.get(self.off_to_range);
        const prev_off_sec_idx = off_idx.prev().get(self.off_to_range);
        // TODO: should consider calculating the padding and treating it as overwritable.
        const existing_gap: u32 = @intCast(sec_idx.get(self.ranges).off - (prev_off_sec_idx.get(self.ranges).off + @min(prev_off_sec_idx.get(self.ranges).filesz, prev_off_sec_idx.get(self.ranges).memsz)));
        if (needed_size < existing_gap) break;
        needed_size -= existing_gap;
        needed_size = align_ceil(u32, needed_size, self.header.file_alignment);
        off_idx.get(self.off_to_range).get(self.ranges).adjust = needed_size;
    }
    off_idx = off_idx;
    while (off_idx != first_adjust_off_idx) {
        off_idx = off_idx.prev();
        const range_idx = off_idx.get(self.off_to_range).*;
        try shift_forward(parse_source, range_idx.get(self.ranges).off, range_idx.get(self.ranges).off + @min(range_idx.get(self.ranges).filesz, range_idx.get(self.ranges).memsz), range_idx.get(self.ranges).adjust);
        range_idx.get(self.ranges).off += range_idx.get(self.ranges).adjust;
        try self.set_filerange_field(range_idx, range_idx.get(self.ranges).off, .off, parse_source);
    }

    if (!edge.is_end) {
        try shift_forward(parse_source, edge.sec_idx.get(self.ranges).off, edge.sec_idx.get(self.ranges).off + @min(edge.sec_idx.get(self.ranges).filesz, edge.sec_idx.get(self.ranges).memsz), new_offset + size - edge.sec_idx.get(self.ranges).off);
        edge.sec_idx.get(self.ranges).addr -= align_ceil(u64, size, self.header.section_alignment);
        try self.set_filerange_field(edge.sec_idx, edge.sec_idx.get(self.ranges).addr, .addr, parse_source);
        edge.sec_idx.get(self.ranges).off = new_offset;
        try self.set_filerange_field(edge.sec_idx, edge.sec_idx.get(self.ranges).off, .off, parse_source);
    }
    const filesz_adjust: u32 = blk: {
        if ((edge.sec_idx.get(self.ranges).filesz - edge.sec_idx.get(self.ranges).memsz) < size) {
            const needed_filsz: u32 = @intCast(size - (edge.sec_idx.get(self.ranges).filesz - edge.sec_idx.get(self.ranges).memsz));
            const res = align_ceil(u32, needed_filsz, self.header.file_alignment);
            edge.sec_idx.get(self.ranges).filesz += res;
            try self.set_filerange_field(edge.sec_idx, edge.sec_idx.get(self.ranges).filesz, .filesz, parse_source);
            break :blk res;
        } else break :blk 0;
    };
    edge.sec_idx.get(self.ranges).memsz += size;
    try self.set_filerange_field(edge.sec_idx, edge.sec_idx.get(self.ranges).memsz, .memsz, parse_source);
    if (edge.sec_idx.get(self.ranges).section_flags.CNT_CODE == 1) {
        self.header.size_of_code += filesz_adjust;
        try self.set_image_optional_header_field(self.header.size_of_code, "size_of_code", parse_source);
    }
    if (edge.sec_idx.get(self.ranges).section_flags.CNT_INITIALIZED_DATA == 1) {
        self.header.size_of_initialized_data += filesz_adjust;
        try self.set_image_optional_header_field(self.header.size_of_initialized_data, "size_of_initialized_data", parse_source);
    }
    if (edge.sec_idx.get(self.ranges).section_flags.CNT_UNINITIALIZED_DATA == 1) {
        self.header.size_of_uninitialized_data += filesz_adjust;
        try self.set_image_optional_header_field(self.header.size_of_uninitialized_data, "size_of_uninitialized_data", parse_source);
    }
    // TODO: might need to adjust some more things.
}

const CompareContext = struct {
    self: *const Modder,
    lhs: u64,
};

fn addr_compareFn(context: CompareContext, rhs: RangeIndex) std.math.Order {
    return std.math.order(context.lhs, rhs.get(context.self.ranges).addr);
}

pub fn addr_to_off(self: *const Modder, addr: u64) Error!u64 {
    const normalized_addr = if (addr < self.header.image_base) return Error.AddrNotMapped else addr - self.header.image_base;
    const containnig_idx = try self.addr_to_idx(normalized_addr);
    if (!(normalized_addr < (containnig_idx.get(self.ranges).addr + containnig_idx.get(self.ranges).memsz))) return Error.AddrNotMapped;
    const potenital_off = containnig_idx.get(self.ranges).off + normalized_addr - containnig_idx.get(self.ranges).addr;
    if (!(potenital_off < (containnig_idx.get(self.ranges).off + containnig_idx.get(self.ranges).filesz))) return Error.NoMatchingOffset;
    return potenital_off;
}

fn addr_to_idx(self: *const Modder, addr: u64) !RangeIndex {
    const lower_bound = std.sort.lowerBound(RangeIndex, self.addr_to_range[0..self.len], CompareContext{ .self = self, .lhs = addr + 1 }, addr_compareFn);
    if (lower_bound == 0) return Error.AddrNotMapped;
    return self.addr_to_range[lower_bound - 1];
}

fn off_compareFn(context: CompareContext, rhs: RangeIndex) std.math.Order {
    return std.math.order(context.lhs, rhs.get(context.self.ranges).off);
}

pub fn off_to_addr(self: *const Modder, off: u64) Error!u64 {
    const containnig_idx = self.off_to_idx(off);
    if (!(off < (containnig_idx.get(self.ranges).off + containnig_idx.get(self.ranges).filesz))) return Error.OffsetNotLoaded;
    if ((containnig_idx.get(self.ranges).memsz < containnig_idx.get(self.ranges).filesz) and ((containnig_idx.get(self.ranges).filesz - containnig_idx.get(self.ranges).memsz) >= self.header.file_alignment)) return Error.VirtualSizeLessThenFileSize;
    return self.header.image_base + containnig_idx.get(self.ranges).addr + off - containnig_idx.get(self.ranges).off;
}

fn off_to_idx(self: *const Modder, off: u64) RangeIndex {
    return self.off_to_range[std.sort.lowerBound(RangeIndex, self.off_to_range[0..self.len], CompareContext{ .self = self, .lhs = off + 1 }, off_compareFn) - 1];
}

pub fn cave_to_off(self: *const Modder, cave: SecEdge, size: u64) u64 {
    return cave.sec_idx.get(self.ranges).off + if (cave.is_end) cave.sec_idx.get(self.ranges).filesz - size else 0;
}

fn set_new_shdr(self: *const Modder, size: u32, flags: FileRangeFlags, off: u32, addr: u32, file: anytype) !void {
    const new_shdr: std.coff.SectionHeader = .{
        .name = .{ '.', 'p', 'a', 't', 'c', 'h', 0, 0 },
        .virtual_size = size,
        .virtual_address = addr,
        .size_of_raw_data = align_ceil(u32, size, self.header.file_alignment),
        .pointer_to_raw_data = off,
        .pointer_to_relocations = 0,
        .pointer_to_linenumbers = 0,
        .number_of_relocations = 0,
        .number_of_linenumbers = 0,
        .flags = .{
            .CNT_CODE = if (flags.execute) 1 else 0,
            .MEM_EXECUTE = if (flags.execute) 1 else 0,
            .MEM_READ = if (flags.read) 1 else 0,
            .MEM_WRITE = if (flags.write) 1 else 0,
        },
    };
    // TODO: figure this out
    // if (self.header.endian != native_endian) {
    //     std.mem.byteSwapAllFields(std.coff.SectionHeader, &new_shdr);
    // }
    const temp = std.mem.toBytes(new_shdr);
    if (try file.write(&temp) != @sizeOf(std.coff.SectionHeader)) return Error.UnexpectedEof;
}

pub fn create_section(self: *Modder, gpa: std.mem.Allocator, size: u32, flags: FileRangeFlags, file: anytype) !void {
    const needed_size: u64 = @sizeOf(std.coff.SectionHeader);
    std.debug.print("\n\nself.ranges[0].memsz = {}\n", .{self.ranges[0].memsz});
    std.debug.print("\n\nself.ranges[0].filesz = {}\n", .{self.ranges[0].filesz});
    if ((self.ranges[0].to_addr.next().get(self.addr_to_range).get(self.ranges).addr - self.ranges[0].memsz) < needed_size) return Error.NoSpaceLeft;
    try self.create_cave(needed_size, .{ .is_end = true, .sec_idx = @enumFromInt(0) }, file);
    std.debug.print("\n\nself.ranges[0].memsz = {}\n", .{self.ranges[0].memsz});
    std.debug.print("\n\nself.ranges[0].filesz = {}\n", .{self.ranges[0].filesz});

    // TODO: consider if the created section should go at the end, but before the overlay (kind of sus in general with having the overlay).
    const last_off_range_idx = self.off_to_range[self.len - 1];
    const max_off = last_off_range_idx.get(self.ranges).off + last_off_range_idx.get(self.ranges).filesz;
    if (max_off != utils.align_ceil(u64, try file.getEndPos(), self.header.file_alignment)) return Error.UnmappedRange;
    const last_addr_range_idx = self.addr_to_range[self.len - 1];
    const max_addr = last_addr_range_idx.get(self.ranges).addr + last_addr_range_idx.get(self.ranges).memsz;
    const secidx = self.len - 2;
    const offset = self.header.coff_header_offset + @sizeOf(std.coff.CoffHeader) + self.header.size_of_optional_header + @sizeOf(std.coff.SectionHeader) * secidx;
    try file.seekTo(offset);
    const aligned_max_off = align_ceil(u64, max_off, self.header.file_alignment);
    const aligned_max_addr = align_ceil(u64, max_addr, self.header.section_alignment);
    const aligned_size = align_ceil(u64, size, self.header.file_alignment);
    try self.set_new_shdr(size, flags, @intCast(aligned_max_off), @intCast(aligned_max_addr), file);
    if (flags.execute) {
        self.header.size_of_code += @intCast(aligned_size);
        try self.set_image_optional_header_field(self.header.size_of_code, "size_of_code", file);
    }
    self.header.size_of_image += @intCast(aligned_size);
    try self.set_image_optional_header_field(self.header.size_of_image, "size_of_image", file);
    try file.seekTo(max_off);
    try file.writer().writeByteNTimes(0, aligned_max_off - max_off + aligned_size);
    // NOTE: This is kind of stupid, should instead keep three numbers which track the index where the new segments start.
    self.off_to_range = (try gpa.realloc(self.off_to_range[0..self.len], self.len + 1)).ptr;
    self.off_to_range[self.len] = @enumFromInt(self.len);
    self.addr_to_range = (try gpa.realloc(self.addr_to_range[0..self.len], self.len + 1)).ptr;
    self.addr_to_range[self.len] = @enumFromInt(self.len);

    self.ranges = (try gpa.realloc(self.ranges[0..self.len], self.len + 1)).ptr;
    self.ranges[self.len] = .{
        .off = aligned_max_off,
        .filesz = aligned_size,
        .addr = aligned_max_addr,
        .memsz = size,
        .flags = flags,
        .section_flags = .{ .CNT_CODE = if (flags.execute) 1 else 0 },
        .to_off = @enumFromInt(self.len),
        .to_addr = @enumFromInt(self.len),
        .adjust = undefined,
    };
    self.len += 1;
}

comptime {
    const optimzes = &.{ "ReleaseSmall", "ReleaseFast", "ReleaseSafe", "Debug" }; // ReleaseSafe seems to be generated without any large caves.
    const targets = &.{ "x86_64-windows", "x86-windows" };
    for (optimzes, 0..) |optimize, i| {
        for (targets, 0..) |target, j| {
            if (!utils.should_add_test("coff create cave same output " ++ target ++ optimize)) continue;
            _ = struct {
                test {
                    const test_src_path = "./tests/hello_world.zig";
                    const expected_stdout = "Run `zig build test` to run the tests.\n";
                    const expected_stderr = "All your codebase are belong to us.\n";
                    const test_with_cave_prefix = "./create_cave_same_output_coff";
                    const cwd: std.fs.Dir = std.fs.cwd();
                    const test_with_cave_filename = test_with_cave_prefix ++ target ++ optimize ++ ".exe";
                    {
                        const build_src_result = try std.process.Child.run(.{
                            .allocator = std.testing.allocator,
                            .argv = &[_][]const u8{ "zig", "build-exe", "-target", target, "-O", optimize, "-ofmt=coff", "-femit-bin=" ++ test_with_cave_filename[2..], test_src_path },
                        });
                        defer std.testing.allocator.free(build_src_result.stdout);
                        defer std.testing.allocator.free(build_src_result.stderr);
                        try std.testing.expect(build_src_result.term == .Exited);
                        try std.testing.expect(build_src_result.stderr.len == 0);
                    }

                    {
                        var f = try cwd.openFile(test_with_cave_filename, .{ .mode = .read_write });
                        defer f.close();
                        var stream = std.io.StreamSource{ .file = f };
                        const wanted_size = if ((i == 1) and (j == 1)) 0x20 else 0x200;
                        const data = try std.testing.allocator.alloc(u8, try stream.getEndPos());
                        defer std.testing.allocator.free(data);
                        try std.testing.expectEqual(stream.getEndPos(), try stream.read(data));
                        const coff = try std.coff.Coff.init(data, false);
                        const parsed = Parsed.init(coff);
                        var coff_modder: Modder = try Modder.init(std.testing.allocator, &parsed, &stream);
                        defer coff_modder.deinit(std.testing.allocator);
                        const option = (try coff_modder.get_cave_option(wanted_size, .{ .read = true, .execute = true })) orelse return Error.NoCaveOption;
                        try coff_modder.create_cave(wanted_size, option, &stream);
                    }

                    if (builtin.os.tag == .windows) {
                        // check output with a cave
                        const cave_result = try std.process.Child.run(.{
                            .allocator = std.testing.allocator,
                            .argv = &[_][]const u8{test_with_cave_filename},
                        });
                        defer std.testing.allocator.free(cave_result.stdout);
                        defer std.testing.allocator.free(cave_result.stderr);
                        try std.testing.expect(cave_result.term == .Exited);
                        try std.testing.expectEqual(0, cave_result.term.Exited);
                        try std.testing.expectEqualStrings(expected_stdout, cave_result.stdout);
                        try std.testing.expectEqualStrings(expected_stderr, cave_result.stderr);
                    }
                    if (builtin.os.tag != .windows) {
                        return error.SkipZigTest;
                    }
                }
            };
        }
    }
}

test "create section same output" {
    const test_src_path = "./tests/hello_world.zig";
    const test_with_cave = "./create_section_same_output_coff.exe";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-target", "x86_64-windows", "-O", "ReleaseSmall", "-ofmt=coff", "-femit-bin=" ++ test_with_cave[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    var maybe_no_cave_result: ?std.process.Child.RunResult = null;
    if (builtin.os.tag == .windows) {
        // check regular output.
        maybe_no_cave_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{test_with_cave},
        });
    }
    defer if (maybe_no_cave_result) |no_cave_result| {
        std.testing.allocator.free(no_cave_result.stdout);
        std.testing.allocator.free(no_cave_result.stderr);
    };

    {
        var f = try cwd.openFile(test_with_cave, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        const wanted_size = 0xfff;
        const data = try std.testing.allocator.alloc(u8, try stream.getEndPos());
        defer std.testing.allocator.free(data);
        try std.testing.expectEqual(stream.getEndPos(), try stream.read(data));
        const coff = try std.coff.Coff.init(data, false);
        const parsed = Parsed.init(coff);
        var coff_modder: Modder = try Modder.init(std.testing.allocator, &parsed, &stream);
        defer coff_modder.deinit(std.testing.allocator);
        try coff_modder.create_section(std.testing.allocator, wanted_size, .{ .execute = true, .read = true, .write = true }, &stream);
    }
    if (builtin.os.tag != .windows) {
        return error.SkipZigTest;
    }

    // check output with a cave
    const cave_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_cave},
    });
    defer std.testing.allocator.free(cave_result.stdout);
    defer std.testing.allocator.free(cave_result.stderr);
    try std.testing.expect(cave_result.term == .Exited);
    try std.testing.expect(maybe_no_cave_result.?.term == .Exited);
    try std.testing.expectEqual(cave_result.term.Exited, maybe_no_cave_result.?.term.Exited);
    try std.testing.expectEqualStrings(cave_result.stdout, maybe_no_cave_result.?.stdout);
    try std.testing.expectEqualStrings(cave_result.stderr, maybe_no_cave_result.?.stderr);
}
