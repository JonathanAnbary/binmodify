//! Provides utilities for modifying ELF's, specificly the get_cave_option(), create_cave(), addr_to_off(), off_to_addr(), cave_to_off() functions.
//! Which are required for a usage with the patch.Patcher structure.

const std = @import("std");
const elf = std.elf;

const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();

const utils = @import("../utils.zig");
const stream_shift_forward = utils.shift_forward;
const FileRangeFlags = utils.FileRangeFlags;
const Parsed = @import("Parsed.zig");

const p_flags_type = std.meta.fieldInfo(elf.Elf64_Phdr, @field(Phdr64Fields, "p_flags")).type;

const PFlags: type = packed struct(p_flags_type) {
    PF_X: bool = false,
    PF_W: bool = false,
    PF_R: bool = false,
    _pad: u29 = 0,

    const Self = @This();

    comptime {
        std.debug.assert(elf.PF_X == @as(p_flags_type, @bitCast(Self{ .PF_X = true })));
        std.debug.assert(elf.PF_W == @as(p_flags_type, @bitCast(Self{ .PF_W = true })));
        std.debug.assert(elf.PF_R == @as(p_flags_type, @bitCast(Self{ .PF_R = true })));
    }
};

const ElfError = error{
    InvalidElfMagic,
    InvalidElfVersion,
    InvalidElfEndian,
    InvalidElfClass,
    EndOfStream,
    OutOfMemory,
};

pub const Error = error{
    EdgeNotFound,
    InvalidEdge,
    InvalidHeader,
    OffsetNotLoaded,
    AddrNotMapped,
    NoMatchingOffset,
    IntersectingFileRanges,
    InvalidElfRanges,
    OverlappingMemoryRanges,
    UnexpectedEof,
    CantExpandPhdr,
    FileszBiggerThenMemsz,
    OutOfBoundField,
    UnmappedRange,
    FieldNotAdjustable,
    PhdrTablePhdrNotFound,
    NoSpaceToExtendPhdrTable,
    TooManyFileRanges,
} || ElfError;

pub const SegEdge: type = struct {
    top_idx: TopIndex,
    is_end: bool,
};

pub const EdgeType = SegEdge;

const Phdr64Fields = std.meta.FieldEnum(elf.Elf64_Phdr);
const Phdr32Fields = std.meta.FieldEnum(elf.Elf32_Phdr);

const Shdr64Fields = std.meta.FieldEnum(elf.Elf64_Shdr);
const Shdr32Fields = std.meta.FieldEnum(elf.Elf32_Shdr);

const Ehdr64Fields = std.meta.FieldEnum(elf.Elf64_Ehdr);
const Ehdr32Fields = std.meta.FieldEnum(elf.Elf32_Ehdr);

fn off_lessThanFn(ranges: []FileRange, lhs: RangeIndex, rhs: RangeIndex) bool {
    return (lhs.get(ranges.ptr).off < rhs.get(ranges.ptr).off) or
        ((lhs.get(ranges.ptr).off == rhs.get(ranges.ptr).off) and
            ((lhs.get(ranges.ptr).filesz > rhs.get(ranges.ptr).filesz) or
                ((lhs.get(ranges.ptr).filesz == rhs.get(ranges.ptr).filesz) and
                    ((lhs.get(ranges.ptr).alignment > rhs.get(ranges.ptr).alignment) or
                        ((lhs.get(ranges.ptr).alignment == rhs.get(ranges.ptr).alignment) and
                            (@intFromEnum(lhs) > @intFromEnum(rhs)))))));
}

// TODO: consider if this should have a similar logic, where segments which "contain" other segments come first.
fn addr_lessThanFn(ranges: []FileRange, lhs: AddrInfo, rhs: AddrInfo) bool {
    return (lhs.to_range.get(ranges.ptr).addr < rhs.to_range.get(ranges.ptr).addr);
}

const FileRange: type = struct {
    off: u64,
    filesz: u64,
    addr: u64, // TODO: should be nullable
    memsz: u64,
    alignment: u64,
    flags: FileRangeFlags,
    to_off: OffIndex,
    to_addr: AddrIndex,
};

const PartialHeader = struct {
    is_64: bool,
    endian: std.builtin.Endian,
    entry: u64,
    phoff: u64,
    shoff: u64,
    phentsize: u16,
    phnum: u16,
    shentsize: u16,
    shnum: u16,
};

const AddrInfo = struct {
    to_range: RangeIndex,
    to_load: LoadIndex,
};

const RangeIndex = utils.Index(FileRange);
const OffIndex = utils.Index(RangeIndex);
const AddrIndex = utils.Index(AddrInfo);

const LoadIndex = utils.Index(AddrIndex);

const TopIndex = utils.Index(OffIndex);

header: PartialHeader,
ranges_len: u16,
ranges: [*]FileRange,
off_to_range: [*]RangeIndex,
addrs_info: [*]AddrInfo,
tops_len: u16,
top_to_off: [*]OffIndex,
adjustments: [*]u64,
load_to_addr: []AddrIndex,

const Modder = @This();

pub fn init(gpa: std.mem.Allocator, parsed: *const Parsed, file: anytype) !Modder {
    // + 1 for the sechdr table which appears to not be contained in any section/segment.
    if (parsed.header.shnum + 1 + parsed.header.phnum > std.math.maxInt(u16)) return Error.TooManyFileRanges;
    const ranges = try gpa.alloc(FileRange, parsed.header.shnum + 1 + parsed.header.phnum);
    errdefer gpa.free(ranges);
    var shdrs_iter = parsed.header.section_header_iterator(file);
    var i: u16 = 0;
    while (try shdrs_iter.next()) |shdr| {
        ranges[i] = .{
            .off = shdr.sh_offset,
            .filesz = if ((shdr.sh_type & elf.SHT_NOBITS) != 0) 0 else shdr.sh_size,
            .addr = shdr.sh_addr,
            .memsz = shdr.sh_size,
            .alignment = shdr.sh_addralign,
            .flags = .{},
            .to_off = undefined,
            .to_addr = undefined,
        };
        i += 1;
    }
    // TODO: consider first checking if its already contained in a range.
    // NOTE: we create an explict file range for the section header table to ensure that it wont be overriden.
    ranges[i] = .{
        .off = parsed.header.shoff,
        .filesz = parsed.header.shentsize * parsed.header.shnum,
        .addr = 0,
        .memsz = 0,
        .alignment = 0,
        .flags = .{},
        .to_off = undefined,
        .to_addr = undefined,
    };
    i += 1;
    var load_count: u16 = 0;
    const load_map = try gpa.alloc(bool, parsed.header.phnum);
    defer gpa.free(load_map);
    var phdrs_iter = parsed.header.program_header_iterator(file);
    var phdr_idx: u16 = 0;
    while (try phdrs_iter.next()) |phdr| : (phdr_idx += 1) {
        const flags: PFlags = @bitCast(phdr.p_flags);
        // NOTE: the docs seem to indicate that PT_TLS should not be loaded based on itself (ie it should overlap with a PT_LOAD)
        // but this does not seem to be the case.
        load_map[phdr_idx] = ((phdr.p_type == elf.PT_LOAD) or (phdr.p_type == elf.PT_TLS));
        if (load_map[phdr_idx]) load_count += 1;
        ranges[i] = .{
            .off = phdr.p_offset,
            .filesz = phdr.p_filesz,
            .addr = phdr.p_vaddr,
            .memsz = phdr.p_memsz,
            .alignment = phdr.p_align,
            .flags = .{
                .read = flags.PF_R,
                .write = flags.PF_W,
                .execute = flags.PF_X,
            },
            .to_off = undefined,
            .to_addr = undefined,
        };
        i += 1;
    }
    var off_to_range = try gpa.alloc(RangeIndex, ranges.len);
    errdefer gpa.free(off_to_range[0..ranges.len]);
    var addrs_info = try gpa.alloc(AddrInfo, ranges.len);
    errdefer gpa.free(addrs_info[0..ranges.len]);
    for (0..ranges.len) |j| {
        off_to_range[j] = @enumFromInt(j);
        addrs_info[j].to_range = @enumFromInt(j);
    }
    std.sort.pdq(RangeIndex, off_to_range, ranges, off_lessThanFn);
    std.sort.pdq(AddrInfo, addrs_info, ranges, addr_lessThanFn);
    for (off_to_range, addrs_info, 0..) |off_idx, addr_info, idx| {
        off_idx.get(ranges.ptr).to_off = @enumFromInt(idx);
        addr_info.to_range.get(ranges.ptr).to_addr = @enumFromInt(idx);
    }
    var off_containing_index = off_to_range[0];
    var off_containing_count: u16 = 1;
    if (off_containing_index.get(ranges.ptr).off != 0) return Error.InvalidElfRanges;
    for (off_to_range[1..]) |index| {
        const off = index.get(ranges.ptr).off;
        if (off >= (off_containing_index.get(ranges.ptr).off + off_containing_index.get(ranges.ptr).filesz)) {
            off_containing_index = index;
            off_containing_count += 1;
        } else {
            if ((off + index.get(ranges.ptr).filesz) > (off_containing_index.get(ranges.ptr).off + off_containing_index.get(ranges.ptr).filesz)) return Error.IntersectingFileRanges;
        }
    }
    const top_to_off = try gpa.alloc(OffIndex, off_containing_count);
    errdefer gpa.free(top_to_off);
    var top_index: TopIndex = @enumFromInt(0);
    off_containing_index = off_to_range[0];
    top_index.get(top_to_off.ptr).* = @enumFromInt(0);
    top_index = top_index.next();
    for (off_to_range[1..], 1..) |index, j| {
        const off = index.get(ranges.ptr).off;
        if (off >= (off_containing_index.get(ranges.ptr).off + off_containing_index.get(ranges.ptr).filesz)) {
            off_containing_index = index;
            top_index.get(top_to_off.ptr).* = @enumFromInt(j);
            top_index = top_index.next();
        }
    }
    const load_to_addr = try gpa.alloc(AddrIndex, load_count);
    var load_index: LoadIndex = @enumFromInt(0);
    errdefer gpa.free(load_to_addr);
    for (addrs_info, 0..) |addr_info, j| {
        if ((@intFromEnum(addr_info.to_range) > parsed.header.shnum) and (load_map[@intFromEnum(addr_info.to_range) - parsed.header.shnum - 1])) {
            if ((@intFromEnum(load_index) != 0) and (addr_info.to_range.get(ranges.ptr).addr < (load_index.prev().get(load_to_addr.ptr).get(addrs_info.ptr).to_range.get(ranges.ptr).addr + load_index.prev().get(load_to_addr.ptr).get(addrs_info.ptr).to_range.get(ranges.ptr).memsz))) {
                return Error.OverlappingMemoryRanges;
            }
            load_index.get(load_to_addr.ptr).* = @enumFromInt(j);
            load_index = load_index.next();
        }
    }

    var prev_load = load_to_addr[0];
    for (load_to_addr[1..], 1..) |load_addr, load_idx| {
        for (@intFromEnum(prev_load)..@intFromEnum(load_addr)) |addr_idx| {
            addrs_info[addr_idx].to_load = @enumFromInt(load_idx - 1);
        }
        prev_load = load_addr;
    }
    for (@intFromEnum(prev_load)..ranges.len) |addr_idx| {
        addrs_info[addr_idx].to_load = @enumFromInt(load_to_addr.len - 1);
    }

    const temp = Modder{
        .header = .{
            .is_64 = parsed.header.is_64,
            .endian = parsed.header.endian,
            .entry = parsed.header.entry,
            .phoff = parsed.header.phoff,
            .shoff = parsed.header.shoff,
            .phentsize = parsed.header.phentsize,
            .phnum = parsed.header.phnum,
            .shentsize = parsed.header.shentsize,
            .shnum = parsed.header.shnum,
        },
        .ranges_len = @intCast(ranges.len),
        .ranges = ranges.ptr,
        .off_to_range = off_to_range.ptr,
        .addrs_info = addrs_info.ptr,
        .tops_len = off_containing_count,
        .top_to_off = top_to_off.ptr,
        .adjustments = (try gpa.alloc(u64, off_containing_count)).ptr,
        .load_to_addr = load_to_addr,
    };

    return temp;
}

pub fn deinit(self: *Modder, gpa: std.mem.Allocator) void {
    gpa.free(self.adjustments[0..self.tops_len]);
    gpa.free(self.addrs_info[0..self.ranges_len]);
    gpa.free(self.load_to_addr);
    gpa.free(self.top_to_off[0..self.tops_len]);
    gpa.free(self.off_to_range[0..self.ranges_len]);
    gpa.free(self.ranges[0..self.ranges_len]);
}

const RangeType: type = enum {
    ProgramHeader,
    SectionHeader,
    SectionHeaderTable,
};

fn range_type(self: *const Modder, index: RangeIndex) RangeType {
    // NOTE: maybe add a check on the phnum as well?
    return if (@intFromEnum(index) < self.header.shnum) .SectionHeader else if (@intFromEnum(index) == self.header.shnum) .SectionHeaderTable else .ProgramHeader;
}

/// Get information for the location within the file where additional data could be inserted.
pub fn get_cave_option(self: *const Modder, wanted_size: u64, flags: FileRangeFlags) !?SegEdge {
    var i: TopIndex = @enumFromInt(self.tops_len);
    while (@intFromEnum(i) > 0) {
        i = i.prev();
        const off_idx = i.get(self.top_to_off);
        const range_idx = off_idx.get(self.off_to_range);
        if (range_idx.get(self.ranges).flags != flags) continue;
        const addr_idx = range_idx.get(self.ranges).to_addr;
        const top_addr_idx = addr_idx.get(self.addrs_info).to_load;
        // NOTE: this assumes you dont have an upper bound on possible memory address.
        if ((@intFromEnum(top_addr_idx) == (self.load_to_addr.len - 1)) or ((range_idx.get(self.ranges).addr + range_idx.get(self.ranges).memsz + wanted_size) < top_addr_idx.next().get(self.load_to_addr.ptr).get(self.addrs_info).to_range.get(self.ranges).addr)) return SegEdge{
            .top_idx = i,
            .is_end = true,
        };
        const prev_seg_mem_bound = if (@intFromEnum(top_addr_idx) == 0) 0 else blk: {
            const prev_top_seg_idx = top_addr_idx.prev().get(self.load_to_addr.ptr).get(self.addrs_info).to_range;
            break :blk (prev_top_seg_idx.get(self.ranges).addr + prev_top_seg_idx.get(self.ranges).memsz);
        };
        if (range_idx.get(self.ranges).addr > (wanted_size + prev_seg_mem_bound)) return SegEdge{
            .top_idx = i,
            .is_end = false,
        };
    }
    return null;
}

fn set_shdr_field(self: *const Modder, index: RangeIndex, val: u64, comptime field_name: []const u8, file: anytype) !void {
    if (@intFromEnum(index) >= self.header.shnum) return Error.OutOfBoundField;
    try file.seekTo(self.header.shoff + self.header.shentsize * @intFromEnum(index));
    if (self.header.is_64) {
        const T = std.meta.fieldInfo(elf.Elf64_Shdr, @field(Shdr64Fields, field_name)).type;
        var temp: T = @intCast(val);
        temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
        try file.seekBy(@offsetOf(elf.Elf64_Shdr, field_name));
        const temp2 = std.mem.toBytes(temp);
        if (try file.write(&temp2) != @sizeOf(T)) return Error.UnexpectedEof;
    } else {
        const T = std.meta.fieldInfo(elf.Elf32_Shdr, @field(Shdr32Fields, field_name)).type;
        var temp: T = @intCast(val);
        temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
        try file.seekBy(@offsetOf(elf.Elf32_Shdr, field_name));
        const temp2 = std.mem.toBytes(temp);
        if (try file.write(&temp2) != @sizeOf(T)) return Error.UnexpectedEof;
    }
    // self.shdrs.items(@field(Shdr64Fields, field_name))[index] = @intCast(val);
}

fn set_ehdr_field(self: *Modder, val: u64, comptime field_name: []const u8, file: anytype) !void {
    const native_field_name = "e_" ++ field_name;
    try file.seekTo(0);
    if (self.header.is_64) {
        const T = std.meta.fieldInfo(elf.Elf64_Ehdr, @field(Ehdr64Fields, native_field_name)).type;
        var temp: T = @intCast(val);
        temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
        try file.seekBy(@offsetOf(elf.Elf64_Ehdr, native_field_name));
        const temp2 = std.mem.toBytes(temp);
        if (try file.write(&temp2) != @sizeOf(T)) return Error.UnexpectedEof;
    } else {
        const T = std.meta.fieldInfo(elf.Elf32_Ehdr, @field(Ehdr32Fields, native_field_name)).type;
        var temp: T = @intCast(val);
        temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
        try file.seekBy(@offsetOf(elf.Elf32_Ehdr, native_field_name));
        const temp2 = std.mem.toBytes(temp);
        if (try file.write(&temp2) != @sizeOf(T)) return Error.UnexpectedEof;
    }
    @field(self.header, field_name) = @intCast(val);
}

// NOTE: field changes must NOT change the memory order or offset order!
// TODO: consider what to do when setting the segment which holds the phdrtable itself.
fn set_phdr_field(self: *const Modder, index: u16, val: u64, comptime field_name: []const u8, file: anytype) !void {
    if (index >= self.header.phnum) return Error.OutOfBoundField;
    try file.seekTo(self.header.phoff + self.header.phentsize * index);
    if (self.header.is_64) {
        const T = std.meta.fieldInfo(elf.Elf64_Phdr, @field(Phdr64Fields, field_name)).type;
        var temp: T = @intCast(val);
        temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
        try file.seekBy(@offsetOf(elf.Elf64_Phdr, field_name));
        const temp2 = std.mem.toBytes(temp);
        if (try file.write(&temp2) != @sizeOf(T)) return Error.UnexpectedEof;
    } else {
        const T = std.meta.fieldInfo(elf.Elf32_Phdr, @field(Phdr32Fields, field_name)).type;
        var temp: T = @intCast(val);
        temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
        try file.seekBy(@offsetOf(elf.Elf32_Phdr, field_name));
        const temp2 = std.mem.toBytes(temp);
        if (try file.write(&temp2) != @sizeOf(T)) return Error.UnexpectedEof;
    }
    // self.phdrs.items(@field(Phdr64Fields, field_name))[index] = @intCast(val);
}

// Calculate a new offset for filerange 'top_idx' with the following constraint (read about p_align from man elf):
// new_off % top_idx.align == (top_idx.addr - size) % top_idx.align.
// Assumes that:
// top_idx.off % top_idx.align == top_idx.addr % top_idx.align.
// Attempts to introduce the least needed IO.
fn calc_new_off(self: *const Modder, top_idx: TopIndex, size: u64) !u64 {
    const index = top_idx.get(self.top_to_off).get(self.off_to_range);

    const align_offset = (index.get(self.ranges).off + (index.get(self.ranges).alignment - (size % index.get(self.ranges).alignment))) % index.get(self.ranges).alignment; // The target value for 'new_off % top_idx.align'
    const prev_idx = top_idx.prev().get(self.top_to_off).get(self.off_to_range);
    const prev_off_end = prev_idx.get(self.ranges).off + prev_idx.get(self.ranges).filesz;
    if (prev_off_end > index.get(self.ranges).off) return Error.IntersectingFileRanges;
    const new_offset = if (index.get(self.ranges).off > (size + prev_off_end))
        (index.get(self.ranges).off - size)
    else
        (prev_off_end + (if ((prev_off_end % index.get(self.ranges).alignment) <= align_offset)
            (align_offset)
        else
            (index.get(self.ranges).alignment + align_offset)) - (prev_off_end % index.get(self.ranges).alignment));
    return new_offset;
}

fn shift_forward(self: *Modder, size: u64, start_top_idx: TopIndex, file: anytype) !void {
    var needed_size = size;
    var top_idx = start_top_idx;
    var adjust_idx: u16 = 0;
    while (@intFromEnum(top_idx) < self.tops_len) : ({
        top_idx = top_idx.next();
        adjust_idx += 1;
    }) {
        const off_range_index = top_idx.get(self.top_to_off);
        const range_index = off_range_index.get(self.off_to_range);
        const prev_off_range_index = top_idx.prev().get(self.top_to_off);
        const prev_range_index = prev_off_range_index.get(self.off_to_range);
        const existing_gap = range_index.get(self.ranges).off - (prev_range_index.get(self.ranges).off + prev_range_index.get(self.ranges).filesz);
        if (needed_size < existing_gap) break;
        needed_size -= existing_gap;
        // TODO: definetly the case that I should be looking at the maximum alignment of all contained ranges here.
        if ((range_index.get(self.ranges).alignment != 0) and ((needed_size % range_index.get(self.ranges).alignment) != 0)) {
            needed_size += range_index.get(self.ranges).alignment - (needed_size % range_index.get(self.ranges).alignment);
        }
        self.adjustments[adjust_idx] = needed_size;
    }
    var top_index = top_idx;
    while (@intFromEnum(top_index) > @intFromEnum(start_top_idx)) {
        top_index = top_index.prev();
        adjust_idx -= 1;
        const top_off_idx = top_index.get(self.top_to_off);
        const top_range_idx = top_off_idx.get(self.off_to_range);
        try stream_shift_forward(file, top_range_idx.get(self.ranges).off, top_range_idx.get(self.ranges).off + top_range_idx.get(self.ranges).filesz, self.adjustments[adjust_idx]);
        const final_off_idx = if (@intFromEnum(top_index.next()) == self.tops_len) self.ranges_len else @intFromEnum(top_index.next().get(self.top_to_off).*);
        for (@intFromEnum(top_off_idx.*)..final_off_idx) |off_idx| {
            const index = self.off_to_range[off_idx];
            index.get(self.ranges).off += self.adjustments[adjust_idx];
            try self.set_filerange_field(index, index.get(self.ranges).off, .off, file);
        }
    }
}

fn set_filerange_field(self: *Modder, index: RangeIndex, val: u64, comptime field: std.meta.FieldEnum(FileRange), file: anytype) !void {
    switch (self.range_type(index)) {
        .SectionHeaderTable => {
            switch (field) {
                .off => {
                    try self.set_ehdr_field(val, "shoff", file);
                },
                else => return Error.FieldNotAdjustable,
            }
        },
        .SectionHeader => {
            const fieldname = switch (field) {
                .off => "sh_offset",
                .addr => "sh_addr",
                else => return Error.FieldNotAdjustable,
            };
            try self.set_shdr_field(index, val, fieldname, file);
        },
        .ProgramHeader => {
            const temp = @intFromEnum(index) - (self.header.shnum + 1);
            switch (field) {
                .off => {
                    try self.set_phdr_field(temp, val, "p_offset", file);
                },
                .addr => {
                    try self.set_phdr_field(temp, val, "p_vaddr", file);
                    try self.set_phdr_field(temp, val, "p_paddr", file);
                },
                .filesz => {
                    try self.set_phdr_field(temp, val, "p_filesz", file);
                },
                .memsz => {
                    try self.set_phdr_field(temp, val, "p_memsz", file);
                },
                else => return Error.FieldNotAdjustable,
            }
        },
    }
}

/// Create a cave of the given size at the specified location.
/// assumes that edge was returned from self.get_cave_option(size), and that the file has not been modified since it was called.
pub fn create_cave(self: *Modder, size: u64, edge: SegEdge, file: anytype) !void {
    // NOTE: moving around the pheader table sounds like a bad idea.
    if (@intFromEnum(edge.top_idx) == 0) return Error.CantExpandPhdr;
    const idx = edge.top_idx.get(self.top_to_off).get(self.off_to_range);
    // const shoff_top_idx = self.off_to_top_idx(self.header.shoff);

    const old_offset: u64 = idx.get(self.ranges).off;
    const new_offset: u64 = if (edge.is_end) old_offset else try self.calc_new_off(edge.top_idx, size);
    const first_adjust = if (edge.is_end) size else if (new_offset < old_offset) size - (old_offset - new_offset) else size + (new_offset - old_offset);
    try self.shift_forward(first_adjust, edge.top_idx.next(), file);

    if (!edge.is_end) {
        const top_off_idx = edge.top_idx.get(self.top_to_off);
        const final_off_idx = if (@intFromEnum(edge.top_idx.next()) == self.tops_len) self.ranges_len else @intFromEnum(edge.top_idx.next().get(self.top_to_off).*);

        // TODO: consider the following
        // if (shoff_top_idx == edge.top_idx) {
        //     try self.set_ehdr_field(self.header.shoff + new_offset + size - old_offset, "shoff", file);
        // }
        try stream_shift_forward(file, old_offset, old_offset + idx.get(self.ranges).filesz, first_adjust);

        idx.get(self.ranges).off = new_offset;
        try self.set_filerange_field(idx.*, idx.get(self.ranges).off, .off, file);

        for (@intFromEnum(top_off_idx.next())..final_off_idx) |off_idx| {
            const index = self.off_to_range[off_idx];
            // TODO: consider the following:
            //
            // if (offs[index] == offs[top_range_idx]) {
            //     if (index < self.header.phnum) {
            //         try self.set_phdr_field(index, fileszs[index] + size, "p_filesz", file);
            //         try self.set_phdr_field(index, fileszs[index] + size, "p_memsz", file);
            //         try self.set_phdr_field(index, addrs[index] - size, "p_vaddr", file);
            //         try self.set_phdr_field(index, addrs[index] - size, "p_paddr", file);
            //         try self.set_phdr_field(index, new_offset, "p_offset");
            //     } else {
            //         try self.set_shdr_field(index - self.header.phnum, fileszs[index] + size, "sh_size", file);
            //         try self.set_shdr_field(index - self.header.phnum, addrs[index] - size, "sh_addr", file);
            //         try self.set_shdr_field(index - self.header.phnum, new_offset, "sh_offset", file);
            //     }
            //     fileszs[index] += size;
            //     addrs[index] -= size;
            //     offs[index] = new_offset;
            // } else {
            index.get(self.ranges).off = index.get(self.ranges).off + first_adjust;
            try self.set_filerange_field(index, index.get(self.ranges).off, .off, file);
            // }
        }
        idx.get(self.ranges).addr -= size;
        try self.set_filerange_field(idx.*, idx.get(self.ranges).addr, .addr, file);
    }
    idx.get(self.ranges).filesz += size;
    idx.get(self.ranges).memsz += size;
    // try self.set_filerange_field(idx, fileszs[idx], .filesz, file)
    // try self.set_filerange_field(idx, memszs[idx], .memsz, file)
    switch (self.range_type(idx.*)) {
        .ProgramHeader => {
            try self.set_phdr_field(@intFromEnum(idx.*) - (self.header.shnum + 1), idx.get(self.ranges).filesz, "p_filesz", file);
            try self.set_phdr_field(@intFromEnum(idx.*) - (self.header.shnum + 1), idx.get(self.ranges).memsz, "p_memsz", file);
        },
        .SectionHeaderTable => {}, // NOTE: This very much does not make sense.
        .SectionHeader => {

            // NOTE: This kind of does not make sense.
            // TODO: consider what to do with a NOBITS section.
            try self.set_shdr_field(idx.*, idx.get(self.ranges).filesz, "sh_size", file);
        },
    }

    // TODO: debug info?)
}

fn set_new_phdr(self: *const Modder, comptime is_64: bool, size: u64, flags: FileRangeFlags, alignment: u64, off: u64, addr: u64, file: anytype) !void {
    const T = if (is_64) elf.Elf64_Phdr else elf.Elf32_Phdr;
    var new_phdr: T = .{
        .p_align = @intCast(alignment), // NOTE: this is sus
        .p_filesz = @intCast(size),
        .p_flags = @bitCast(PFlags{
            .PF_R = flags.read,
            .PF_W = flags.write,
            .PF_X = flags.execute,
        }),
        .p_memsz = @intCast(size),
        .p_offset = @intCast(off),
        .p_paddr = @intCast(addr),
        .p_vaddr = @intCast(addr),
        .p_type = elf.PT_LOAD,
    };

    if (self.header.endian != native_endian) {
        std.mem.byteSwapAllFields(T, &new_phdr);
    }
    const temp = std.mem.toBytes(new_phdr);
    if (try file.write(&temp) != @sizeOf(T)) return Error.UnexpectedEof;
}

// This still does not work!
// Need to change the logic such that the top filerange containing the phdr_table and then within that top filerange extend
// the specific filerange of the phdr_table.
// This will only ever work if there is address space between the end of the phdr_table and the next segment.
fn create_segment(self: *Modder, gpa: std.mem.Allocator, size: u64, flags: FileRangeFlags, file: anytype) !void {
    const phdr_top_idx = self.off_to_top_idx(self.header.phoff);
    const top_off_idx = phdr_top_idx.get(self.top_to_off);
    const top_range_idx = top_off_idx.get(self.off_to_range);

    var needed_size: u64 = self.header.phentsize;
    if ((top_range_idx.get(self.ranges).alignment != 0) and ((needed_size % top_range_idx.get(self.ranges).alignment) != 0)) {
        needed_size += top_range_idx.get(self.ranges).alignment - (needed_size % top_range_idx.get(self.ranges).alignment);
    }
    const final_off_idx: OffIndex = blk: {
        if (@intFromEnum(phdr_top_idx.next()) == self.tops_len) {
            break :blk @enumFromInt(self.ranges_len);
        } else {
            const post_off_idx = phdr_top_idx.next().get(self.top_to_off);
            break :blk post_off_idx.*;
        }
    };

    const phdr_off_idx: OffIndex = @enumFromInt(std.sort.lowerBound(
        RangeIndex,
        self.off_to_range[@intFromEnum(top_off_idx.*)..@intFromEnum(final_off_idx)],
        CompareContext{ .self = self, .lhs = self.header.phoff + 1 },
        off_compareFn,
    ) - 1 + @intFromEnum(top_off_idx.*));
    const phdr_range_idx = phdr_off_idx.get(self.off_to_range);
    const phdr_addr_idx = phdr_range_idx.get(self.ranges).to_addr;
    const phdr_load_idx = phdr_addr_idx.get(self.addrs_info).to_load;
    const phdr_is_contained = ((top_range_idx.get(self.ranges).addr + top_range_idx.get(self.ranges).memsz) != (phdr_range_idx.get(self.ranges).addr + phdr_range_idx.get(self.ranges).memsz));
    const have_forward_space = (top_range_idx.get(self.ranges).addr + top_range_idx.get(self.ranges).memsz + needed_size) < phdr_load_idx.next().get(self.load_to_addr.ptr).get(self.addrs_info).to_range.get(self.ranges).addr;
    const have_back_space = top_range_idx.get(self.ranges).addr > needed_size;
    if ((!have_back_space) and (phdr_is_contained or !have_forward_space)) return Error.NoSpaceToExtendPhdrTable;

    if ((phdr_range_idx.get(self.ranges).off + phdr_range_idx.get(self.ranges).filesz) != (self.header.phoff + self.header.phentsize * self.header.phnum)) {
        return Error.PhdrTablePhdrNotFound;
    }
    try self.shift_forward(needed_size, phdr_top_idx.next(), file);
    try stream_shift_forward(
        file,
        self.header.phoff + self.header.phentsize * self.header.phnum,
        top_range_idx.get(self.ranges).off + top_range_idx.get(self.ranges).filesz,
        needed_size,
    );
    top_range_idx.get(self.ranges).filesz += needed_size;
    try self.set_filerange_field(top_range_idx.*, top_range_idx.get(self.ranges).filesz, .filesz, file);
    top_range_idx.get(self.ranges).memsz += needed_size;
    try self.set_filerange_field(top_range_idx.*, top_range_idx.get(self.ranges).memsz, .memsz, file);

    phdr_range_idx.get(self.ranges).filesz += self.header.phentsize;
    try self.set_filerange_field(phdr_range_idx.*, phdr_range_idx.get(self.ranges).filesz, .filesz, file);
    phdr_range_idx.get(self.ranges).memsz += self.header.phentsize;
    try self.set_filerange_field(phdr_range_idx.*, phdr_range_idx.get(self.ranges).memsz, .memsz, file);

    for (@intFromEnum(phdr_off_idx.next())..@intFromEnum(final_off_idx)) |off_idx| {
        const off_index: OffIndex = @enumFromInt(off_idx);
        const index = off_index.get(self.off_to_range);
        index.get(self.ranges).off += needed_size;
        try self.set_filerange_field(index.*, index.get(self.ranges).off, .off, file);
    }

    if (!have_forward_space) {
        top_range_idx.get(self.ranges).addr -= needed_size;
        try self.set_filerange_field(top_range_idx.*, top_range_idx.get(self.ranges).addr, .addr, file);
        phdr_range_idx.get(self.ranges).addr -= needed_size; // self.header.phentsize;
        try self.set_filerange_field(phdr_range_idx.*, phdr_range_idx.get(self.ranges).addr, .addr, file);
    }

    const last_off_range_idx = self.top_to_off[self.tops_len - 1].get(self.off_to_range);
    const max_off = last_off_range_idx.get(self.ranges).off + last_off_range_idx.get(self.ranges).filesz;
    if (max_off != try file.getEndPos()) return Error.UnmappedRange;
    const last_addr_range_idx = self.load_to_addr[self.load_to_addr.len - 1].get(self.addrs_info).to_range;
    const max_addr = last_addr_range_idx.get(self.ranges).addr + last_addr_range_idx.get(self.ranges).memsz;
    try file.seekTo(self.header.phoff + self.header.phentsize * self.header.phnum);
    const alignment = 0x1000;
    const alignment_addend = blk: {
        if ((max_off % alignment) > (max_addr % alignment)) {
            break :blk (max_off % alignment) - (max_addr % alignment);
        } else if ((max_off % alignment) < (max_addr % alignment)) {
            break :blk alignment + (max_off % alignment) - (max_addr % alignment);
        } else break :blk 0;
    };
    if (self.header.is_64) {
        try self.set_new_phdr(true, size, flags, alignment, max_off, max_addr + alignment_addend, file);
    } else {
        try self.set_new_phdr(false, size, flags, alignment, max_off, max_addr + alignment_addend, file);
    }
    self.header.phnum += 1;
    try self.set_ehdr_field(self.header.phnum, "phnum", file);
    try file.seekTo(max_off);
    try file.writer().writeByteNTimes(0, size);
    // NOTE: This is kind of stupid, should instead keep three numbers which track the index where the new segments start.
    self.off_to_range = (try gpa.realloc(self.off_to_range[0..self.ranges_len], self.ranges_len + 1)).ptr;
    self.off_to_range[self.ranges_len] = @enumFromInt(self.ranges_len);
    self.addrs_info = (try gpa.realloc(self.addrs_info[0..self.ranges_len], self.ranges_len + 1)).ptr;
    self.addrs_info[self.ranges_len] = .{
        .to_range = @enumFromInt(self.ranges_len),
        .to_load = @enumFromInt(self.load_to_addr.len),
    };
    self.adjustments = (try gpa.realloc(self.adjustments[0..self.tops_len], self.tops_len + 1)).ptr;
    self.top_to_off = (try gpa.realloc(self.top_to_off[0..self.tops_len], self.tops_len + 1)).ptr;
    self.top_to_off[self.tops_len] = @enumFromInt(self.ranges_len);
    self.tops_len += 1;
    self.load_to_addr = try gpa.realloc(self.load_to_addr, self.load_to_addr.len + 1);
    self.load_to_addr[self.load_to_addr.len - 1] = @enumFromInt(self.ranges_len);
    self.ranges = (try gpa.realloc(self.ranges[0..self.ranges_len], self.ranges_len + 1)).ptr;
    self.ranges[self.ranges_len] = .{
        .addr = max_addr + alignment_addend,
        .off = max_off,
        .flags = flags,
        .alignment = alignment,
        .filesz = size,
        .memsz = size,
        .to_addr = @enumFromInt(self.ranges_len),
        .to_off = @enumFromInt(self.ranges_len),
    };
    self.ranges_len += 1;
}

const CompareContext = struct {
    self: *const Modder,
    lhs: u64,
};

fn addr_compareFn(context: CompareContext, rhs: AddrIndex) std.math.Order {
    return std.math.order(context.lhs, rhs.get(context.self.addrs_info).to_range.get(context.self.ranges).addr);
}

pub fn addr_to_off(self: *const Modder, addr: u64) !u64 {
    const containnig_idx = try self.addr_to_idx(addr);
    if (addr >= (containnig_idx.get(self.ranges).addr + containnig_idx.get(self.ranges).memsz)) return Error.AddrNotMapped;
    const potenital_off = containnig_idx.get(self.ranges).off + addr - containnig_idx.get(self.ranges).addr;
    if (potenital_off >= (containnig_idx.get(self.ranges).off + containnig_idx.get(self.ranges).filesz)) return Error.NoMatchingOffset;
    return potenital_off;
}

fn addr_to_idx(self: *const Modder, addr: u64) !RangeIndex {
    const lower_bound = std.sort.lowerBound(AddrIndex, self.load_to_addr, CompareContext{ .self = self, .lhs = addr + 1 }, addr_compareFn);
    if (lower_bound == 0) return Error.AddrNotMapped;
    return self.load_to_addr[lower_bound - 1].get(self.addrs_info).to_range;
}

fn top_off_compareFn(context: CompareContext, rhs: OffIndex) std.math.Order {
    return std.math.order(context.lhs, rhs.get(context.self.off_to_range).get(context.self.ranges).off);
}

fn off_compareFn(context: CompareContext, rhs: RangeIndex) std.math.Order {
    return std.math.order(context.lhs, rhs.get(context.self.ranges).off);
}

pub fn off_to_addr(self: *const Modder, off: u64) !u64 {
    const containnig_idx = self.off_to_top_idx(off).get(self.top_to_off).get(self.off_to_range);
    if (!(off < (containnig_idx.get(self.ranges).off + containnig_idx.get(self.ranges).filesz))) return Error.OffsetNotLoaded;
    // NOTE: cant think of a case where the memsz will be smaller then the filesz (of a top level segment?).
    if (containnig_idx.get(self.ranges).memsz < containnig_idx.get(self.ranges).filesz) return Error.FileszBiggerThenMemsz;
    return containnig_idx.get(self.ranges).addr + off - containnig_idx.get(self.ranges).off;
}

/// return the offset of the start of the cave described by `cave` and `size`.
/// assumes that create_cave has been called with cave and size, and returned successfully.
pub fn cave_to_off(self: *const Modder, cave: SegEdge, size: u64) u64 {
    const idx = cave.top_idx.get(self.top_to_off).get(self.off_to_range);
    return idx.get(self.ranges).off + if (cave.is_end) idx.get(self.ranges).filesz - size else 0;
}

fn off_to_top_idx(self: *const Modder, off: u64) TopIndex {
    return @enumFromInt(std.sort.lowerBound(OffIndex, self.top_to_off[0..self.tops_len], CompareContext{ .self = self, .lhs = off + 1 }, top_off_compareFn) - 1);
}

pub fn print_modelf(elf_modder: *const Modder) void {
    const offs = elf_modder.ranges.items(.off);
    const addrs = elf_modder.ranges.items(.addr);
    const fileszs = elf_modder.ranges.items(.filesz);
    const memszs = elf_modder.ranges.items(.memsz);
    std.debug.print("\n", .{});
    std.debug.print("{X}", .{offs[0]});
    for (elf_modder.off_to_range[1..elf_modder.ranges.len]) |idx| {
        std.debug.print("-{X}", .{offs[idx]});
    }
    std.debug.print("\n", .{});
    std.debug.print("{}", .{elf_modder.top_to_off[0]});
    for (elf_modder.top_to_off[1..]) |idx| {
        std.debug.print("-{}", .{idx});
    }
    std.debug.print("\n", .{});

    std.debug.print("\noff file ranges:\n", .{});
    for (elf_modder.top_to_off, 0..) |top_off, i| {
        const index = elf_modder.off_to_range[top_off];
        var print_index: RangeIndex = undefined;
        var name: [*:0]const u8 = undefined;
        switch (elf_modder.range_type(index)) {
            .SectionHeader => {
                name = "shdr";
                print_index = index;
            },
            .SectionHeaderTable => {
                name = "shdr_table";
                print_index = 0;
            },
            .ProgramHeader => {
                name = "phdr";
                print_index = index - (elf_modder.header.shnum + 1);
            },
        }
        std.debug.print("top = {s}[{}].off = {X}, .addr = {X}:\n", .{
            name,
            print_index,
            offs[index],
            addrs[index],
        });
        const end = if ((i + 1) == elf_modder.top_to_off.len) elf_modder.ranges.len else elf_modder.top_to_off[i + 1];
        for (elf_modder.off_to_range[top_off..end]) |range_idx| {
            switch (elf_modder.range_type(range_idx)) {
                .SectionHeader => {
                    name = "shdr";
                    print_index = range_idx;
                },
                .SectionHeaderTable => {
                    name = "shdr_table";
                    print_index = 0;
                },
                .ProgramHeader => {
                    name = "phdr";
                    print_index = range_idx - (elf_modder.header.shnum + 1);
                },
            }
            std.debug.print("\t{s}[{}].off = {X}, .addr = {X}, .fsize = {X}, .msize = {X}\n", .{
                name,
                print_index,
                offs[range_idx],
                addrs[range_idx],
                fileszs[range_idx],
                memszs[range_idx],
            });
        }
        std.debug.print("\n", .{});
    }
    std.debug.print("\nload ranges:\n", .{});
    for (elf_modder.load_to_addr, 0..) |load_range, i| {
        const index = elf_modder.addrs_info[load_range].to_range;
        var print_index: RangeIndex = undefined;
        var name: [*:0]const u8 = undefined;
        switch (elf_modder.range_type(index)) {
            .SectionHeader => {
                name = "shdr";
                print_index = index;
            },
            .SectionHeaderTable => {
                name = "shdr_table";
                print_index = 0;
            },
            .ProgramHeader => {
                name = "phdr";
                print_index = index - (elf_modder.header.shnum + 1);
            },
        }
        std.debug.print("load_range = {s}[{}].off = {X}, .addr = {X}:\n", .{
            name,
            print_index,
            offs[index],
            addrs[index],
        });
        const end = if ((i + 1) == elf_modder.load_to_addr.len) elf_modder.ranges.len else elf_modder.load_to_addr[i + 1];
        for (elf_modder.addrs_info[load_range..end]) |addr_info| {
            switch (elf_modder.range_type(addr_info.to_range)) {
                .SectionHeader => {
                    name = "shdr";
                    print_index = addr_info.to_range;
                },
                .SectionHeaderTable => {
                    name = "shdr_table";
                    print_index = 0;
                },
                .ProgramHeader => {
                    name = "phdr";
                    print_index = addr_info.to_range - (elf_modder.header.shnum + 1);
                },
            }
            std.debug.print("\t{s}[{}].off = {X}, .addr = {X}, .fsize = {X}, .msize = {X}\n", .{
                name,
                print_index,
                offs[addr_info.to_range],
                addrs[addr_info.to_range],
                fileszs[addr_info.to_range],
                memszs[addr_info.to_range],
            });
        }
        std.debug.print("\n", .{});
    }
}

comptime {
    const optimzes = &.{ "ReleaseSmall", "ReleaseSafe", "ReleaseFast", "Debug" };
    const targets = &.{ "x86_64-linux", "x86-linux", "aarch64-linux", "arm-linux" };
    const qemus = &.{ "qemu-x86_64", "qemu-i386", "qemu-aarch64", "qemu-arm" };
    for (optimzes) |optimize| {
        for (targets, qemus) |target, qemu| {
            if (!utils.should_add_test("elf create cave same output " ++ target ++ optimize)) continue;
            _ = struct {
                test {
                    const test_src_path = "./tests/hello_world.zig";
                    const expected_stdout = "Run `zig build test` to run the tests.\n";
                    const expected_stderr = "All your codebase are belong to us.\n";
                    const test_with_cave_prefix = "./create_cave_same_output_elf";
                    const cwd: std.fs.Dir = std.fs.cwd();
                    const test_with_cave_filename = test_with_cave_prefix ++ target ++ optimize;
                    {
                        const build_src_result = try std.process.Child.run(.{
                            .allocator = std.testing.allocator,
                            .argv = &[_][]const u8{ "zig", "build-exe", "-target", target, "-O", optimize, "-ofmt=elf", "-femit-bin=" ++ test_with_cave_filename[2..], test_src_path },
                        });
                        defer std.testing.allocator.free(build_src_result.stdout);
                        defer std.testing.allocator.free(build_src_result.stderr);
                        try std.testing.expect(build_src_result.term == .Exited);
                        try std.testing.expect(build_src_result.stderr.len == 0);
                    }

                    {
                        var f = try cwd.openFile(test_with_cave_filename, .{ .mode = .read_write });
                        defer f.close();
                        const wanted_size = 0xfff;
                        const parsed = try Parsed.init(&f);
                        var elf_modder: Modder = try Modder.init(std.testing.allocator, &parsed, &f);
                        defer elf_modder.deinit(std.testing.allocator);
                        const option = (try elf_modder.get_cave_option(wanted_size, .{ .execute = true, .read = true })) orelse return error.NoCaveOption;
                        try elf_modder.create_cave(wanted_size, option, &f);
                    }

                    if (builtin.os.tag == .linux) {
                        // check output with a cave
                        const cave_result = try std.process.Child.run(.{
                            .allocator = std.testing.allocator,
                            .argv = &[_][]const u8{ qemu, test_with_cave_filename },
                        });
                        defer std.testing.allocator.free(cave_result.stdout);
                        defer std.testing.allocator.free(cave_result.stderr);
                        try std.testing.expect(cave_result.term == .Exited);
                        try std.testing.expectEqual(0, cave_result.term.Exited);
                        try std.testing.expectEqualStrings(expected_stdout, cave_result.stdout);
                        try std.testing.expectEqualStrings(expected_stderr, cave_result.stderr);
                    } else {
                        return error.SkipZigTest;
                    }
                }
            };
        }
    }
}

test "corrupted elf (non containied overlapping ranges)" {
    const test_src_path = "./tests/hello_world.zig";
    const test_with_cave = "./corrupted_elf";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-O", "ReleaseSmall", "-ofmt=elf", "-femit-bin=" ++ test_with_cave[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    var f = try cwd.openFile(test_with_cave, .{ .mode = .read_write });
    defer f.close();
    try f.seekTo(0x98);
    const patch = std.mem.toBytes(@as(u64, 0xAF5));
    try std.testing.expectEqual(patch.len, try f.write(&patch));
    const parsed = try Parsed.init(&f);
    try std.testing.expectError(Error.IntersectingFileRanges, Modder.init(std.testing.allocator, &parsed, &f));
}

test "repeated cave expansion equal to single cave" {
    const test_src_path = "./tests/hello_world.zig";
    const test_with_repeated_cave = "./create_repeated_cave_same_output_elf";
    const test_with_non_repeated_cave = "./create_non_repeated_cave_same_output_elf";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-O", "ReleaseSmall", "-ofmt=elf", "-femit-bin=" ++ test_with_repeated_cave[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    try cwd.copyFile(test_with_repeated_cave, cwd, test_with_non_repeated_cave, .{});
    var f_repeated = try cwd.openFile(test_with_repeated_cave, .{ .mode = .read_write });
    defer f_repeated.close();
    const sum = blk: {
        var prng = std.Random.DefaultPrng.init(42);
        const parsed = try Parsed.init(&f_repeated);
        var elf_modder: Modder = try Modder.init(std.testing.allocator, &parsed, &f_repeated);
        defer elf_modder.deinit(std.testing.allocator);
        var temp_sum: u32 = 0;
        for (0..10) |_| {
            const wanted_size = prng.random().intRangeAtMost(u8, 10, 100);
            const option = (try elf_modder.get_cave_option(wanted_size, .{ .execute = true, .read = true })) orelse return error.NoCaveOption;
            try elf_modder.create_cave(wanted_size, option, &f_repeated);
            temp_sum += wanted_size;
        }
        break :blk temp_sum;
    };
    var f_non_repeated = try cwd.openFile(test_with_non_repeated_cave, .{ .mode = .read_write });
    defer f_non_repeated.close();
    {
        const parsed = try Parsed.init(&f_non_repeated);
        var elf_modder: Modder = try Modder.init(std.testing.allocator, &parsed, &f_non_repeated);
        defer elf_modder.deinit(std.testing.allocator);
        const option = (try elf_modder.get_cave_option(sum, .{ .execute = true, .read = true })) orelse return error.NoCaveOption;
        try elf_modder.create_cave(sum, option, &f_non_repeated);
    }
    try f_repeated.seekTo(0);
    try f_non_repeated.seekTo(0);
    var buf1: [0x1000]u8 = undefined;
    var buf2: [0x1000]u8 = undefined;
    var read_amt1 = try f_repeated.readAll(&buf1);
    while (read_amt1 != 0) : (read_amt1 = try f_repeated.readAll(&buf1)) {
        const read_amt2 = try f_non_repeated.readAll(&buf2);
        try std.testing.expectEqualSlices(u8, buf2[0..read_amt2], buf1[0..read_amt1]);
    }
    try std.testing.expectEqual(try f_non_repeated.getEndPos(), try f_non_repeated.getPos());
}

test "create segment same output" {
    const test_src_path = "./tests/hello_world.zig";
    const test_with_cave = "./create_segment_same_output_elf";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-O", "ReleaseSmall", "-ofmt=elf", "-femit-bin=" ++ test_with_cave[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    var maybe_no_cave_result: ?std.process.Child.RunResult = null;
    if (builtin.os.tag == .linux) {
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
        const parsed = try Parsed.init(&stream);
        var elf_modder: Modder = try Modder.init(std.testing.allocator, &parsed, &stream);
        defer elf_modder.deinit(std.testing.allocator);
        try elf_modder.create_segment(std.testing.allocator, wanted_size, .{ .execute = true, .read = true, .write = true }, &stream);
    }
    if (builtin.os.tag != .linux) {
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
