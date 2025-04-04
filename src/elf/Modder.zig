//! Provides utilities for modifying ELF's, specificly the get_cave_option(), create_cave(), addr_to_off(), off_to_addr(), cave_to_off() functions.
//! Which are required for a usage with the patch.Patcher structure.

const std = @import("std");
const elf = std.elf;

const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();

const shift = @import("../shift.zig");
const FileRangeFlags = @import("../file_range_flags.zig").FileRangeFlags;
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

fn off_lessThanFn(ranges: *std.MultiArrayList(FileRange), lhs: RangeIndex, rhs: RangeIndex) bool {
    const offs = ranges.items(.off);
    const fileszs = ranges.items(.filesz);
    const aligns = ranges.items(.alignment);
    return (offs[lhs] < offs[rhs]) or
        ((offs[lhs] == offs[rhs]) and
            ((fileszs[lhs] > fileszs[rhs]) or
                ((fileszs[lhs] == fileszs[rhs]) and
                    ((aligns[lhs] > aligns[rhs]) or
                        ((aligns[lhs] == aligns[rhs]) and
                            (lhs > rhs))))));
}

// TODO: consider if this should have a similar logic, where segments which "contain" other segments come first.
fn addr_lessThanFn(ranges: *std.MultiArrayList(FileRange), lhs: RangeIndex, rhs: RangeIndex) bool {
    const addrs = ranges.items(.addr);
    return (addrs[lhs] < addrs[rhs]);
}

const FileRange: type = struct {
    off: u64,
    filesz: u64,
    addr: u64, // TODO: should be nullable
    memsz: u64,
    alignment: u64,
    flags: FileRangeFlags,
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

const RangeIndex = u16;
const OffIndex = u16;
const AddrIndex = u16;

const LoadIndex = u16;

const TopIndex = u16;

header: PartialHeader,
ranges: std.MultiArrayList(FileRange),
off_to_range: [*]RangeIndex,
addr_to_range: [*]RangeIndex,
range_to_off: [*]OffIndex,
range_to_addr: [*]AddrIndex,
addr_to_load: [*]LoadIndex,
top_to_off: []OffIndex,
adjustments: [*]u64,
load_to_addr: []AddrIndex,

const Modder = @This();

pub fn init(gpa: std.mem.Allocator, parsed: *const Parsed, file: anytype) !Modder {
    var ranges = std.MultiArrayList(FileRange){};
    errdefer ranges.deinit(gpa);
    // + 1 for the sechdr table which appears to not be contained in any section/segment.
    if (parsed.header.shnum + 1 + parsed.header.phnum > std.math.maxInt(RangeIndex)) return Error.TooManyFileRanges;
    try ranges.setCapacity(gpa, parsed.header.shnum + 1 + parsed.header.phnum);
    var shdrs_iter = parsed.header.section_header_iterator(file);
    while (try shdrs_iter.next()) |shdr| {
        ranges.appendAssumeCapacity(FileRange{
            .off = shdr.sh_offset,
            .filesz = if ((shdr.sh_type & elf.SHT_NOBITS) != 0) 0 else shdr.sh_size,
            .addr = shdr.sh_addr,
            .memsz = shdr.sh_size,
            .alignment = shdr.sh_addralign,
            .flags = .{},
        });
    }
    // TODO: consider first checking if its already contained in a range.
    // NOTE: we create an explict file range for the section header table to ensure that it wont be overriden.
    ranges.appendAssumeCapacity(FileRange{
        .off = parsed.header.shoff,
        .filesz = parsed.header.shentsize * parsed.header.shnum,
        .addr = 0,
        .memsz = 0,
        .alignment = 0,
        .flags = .{},
    });
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
        ranges.appendAssumeCapacity(FileRange{
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
        });
    }
    var off_to_range = try gpa.alloc(RangeIndex, ranges.len);
    errdefer gpa.free(off_to_range[0..ranges.len]);
    var addr_to_range = try gpa.alloc(RangeIndex, ranges.len);
    errdefer gpa.free(addr_to_range[0..ranges.len]);
    for (0..ranges.len) |i| {
        off_to_range[i] = @intCast(i);
        addr_to_range[i] = @intCast(i);
    }
    std.sort.pdq(RangeIndex, off_to_range, &ranges, off_lessThanFn);
    std.sort.pdq(RangeIndex, addr_to_range, &ranges, addr_lessThanFn);
    const range_to_off = try gpa.alloc(OffIndex, ranges.len);
    errdefer gpa.free(range_to_off[0..ranges.len]);
    const range_to_addr = try gpa.alloc(AddrIndex, ranges.len);
    errdefer gpa.free(range_to_addr[0..ranges.len]);
    for (off_to_range, addr_to_range, 0..) |off_idx, addr_idx, idx| {
        range_to_off[off_idx] = @intCast(idx);
        range_to_addr[addr_idx] = @intCast(idx);
    }
    const offs = ranges.items(.off);
    const fileszs = ranges.items(.filesz);
    var off_containing_index = off_to_range[0];
    var off_containing_count: usize = 1;
    if (offs[off_containing_index] != 0) return Error.InvalidElfRanges;
    for (off_to_range[1..]) |index| {
        const idx = index;
        const off = offs[idx];
        if (off >= (offs[off_containing_index] + fileszs[off_containing_index])) {
            off_containing_index = idx;
            off_containing_count += 1;
        } else {
            if ((off + fileszs[idx]) > (offs[off_containing_index] + fileszs[off_containing_index])) return Error.IntersectingFileRanges;
        }
    }
    const top_to_off = try gpa.alloc(OffIndex, off_containing_count);
    errdefer gpa.free(top_to_off);
    off_containing_count = 0;
    off_containing_index = off_to_range[0];
    top_to_off[off_containing_count] = 0;
    off_containing_count += 1;
    for (off_to_range[1..], 1..) |index, i| {
        const idx = index;
        const off = offs[idx];
        if (off >= (offs[off_containing_index] + fileszs[off_containing_index])) {
            off_containing_index = idx;
            top_to_off[off_containing_count] = @intCast(i);
            off_containing_count += 1;
        }
    }
    const addrs = ranges.items(.addr);
    const memszs = ranges.items(.memsz);
    const load_to_addr = try gpa.alloc(AddrIndex, load_count);
    var load_index: LoadIndex = 0;
    errdefer gpa.free(load_to_addr);
    for (addr_to_range, 0..) |index, i| {
        if (index < (parsed.header.shnum + 1)) continue;
        if (load_map[index - (parsed.header.shnum + 1)]) {
            if ((load_index != 0) and (addrs[index] < (addrs[addr_to_range[load_to_addr[load_index - 1]]] + memszs[addr_to_range[load_to_addr[load_index - 1]]]))) {
                return Error.OverlappingMemoryRanges;
            }
            load_to_addr[load_index] = @intCast(i);
            load_index += 1;
        }
    }

    const addr_to_load = try gpa.alloc(LoadIndex, ranges.len);
    errdefer gpa.free(addr_to_load[0..ranges.len]);
    var prev_load = load_to_addr[0];
    for (load_to_addr[1..], 1..) |load_addr, load_idx| {
        for (prev_load..load_addr) |addr_idx| {
            addr_to_load[addr_idx] = @intCast(load_idx - 1);
        }
        prev_load = load_addr;
    }
    for (prev_load..ranges.len) |addr_idx| {
        addr_to_load[addr_idx] = @intCast(load_to_addr.len - 1);
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
        .ranges = ranges,
        .off_to_range = off_to_range.ptr,
        .addr_to_range = addr_to_range.ptr,
        .range_to_off = range_to_off.ptr,
        .range_to_addr = range_to_addr.ptr,
        .addr_to_load = addr_to_load.ptr,
        .top_to_off = top_to_off,
        .adjustments = (try gpa.alloc(u64, off_containing_count)).ptr,
        .load_to_addr = load_to_addr,
    };

    return temp;
}

pub fn deinit(self: *Modder, gpa: std.mem.Allocator) void {
    gpa.free(self.adjustments[0..self.top_to_off.len]);
    gpa.free(self.addr_to_load[0..self.ranges.len]);
    gpa.free(self.load_to_addr);
    gpa.free(self.top_to_off);
    gpa.free(self.range_to_addr[0..self.ranges.len]);
    gpa.free(self.range_to_off[0..self.ranges.len]);
    gpa.free(self.addr_to_range[0..self.ranges.len]);
    gpa.free(self.off_to_range[0..self.ranges.len]);
    self.ranges.deinit(gpa);
}

const RangeType: type = enum {
    ProgramHeader,
    SectionHeader,
    SectionHeaderTable,
};

fn range_type(self: *const Modder, index: RangeIndex) RangeType {
    // NOTE: maybe add a check on the phnum as well?
    return if (index < self.header.shnum) .SectionHeader else if (index == self.header.shnum) .SectionHeaderTable else .ProgramHeader;
}

/// Get information for the location within the file where additional data could be inserted.
pub fn get_cave_option(self: *const Modder, wanted_size: u64, flags: FileRangeFlags) !?SegEdge {
    const flagss = self.ranges.items(.flags);
    const addrs = self.ranges.items(.addr);
    const memszs = self.ranges.items(.memsz);
    var i = self.top_to_off.len;
    while (i > 0) {
        i -= 1;
        const off_idx = self.top_to_off[i];
        const range_idx = self.off_to_range[off_idx];
        if (flagss[range_idx] != flags) continue;
        const addr_idx = self.range_to_addr[range_idx];
        const top_addr_idx = self.addr_to_load[addr_idx];
        // NOTE: this assumes you dont have an upper bound on possible memory address.
        if ((top_addr_idx == (self.load_to_addr.len - 1)) or ((addrs[range_idx] + memszs[range_idx] + wanted_size) < addrs[self.addr_to_range[self.load_to_addr[top_addr_idx + 1]]])) return SegEdge{
            .top_idx = @intCast(i),
            .is_end = true,
        };
        const prev_seg_mem_bound = if (top_addr_idx == 0) 0 else blk: {
            const prev_top_seg_idx = self.addr_to_range[self.load_to_addr[top_addr_idx - 1]];
            break :blk (addrs[prev_top_seg_idx] + memszs[prev_top_seg_idx]);
        };
        if (addrs[range_idx] > (wanted_size + prev_seg_mem_bound)) return SegEdge{
            .top_idx = @intCast(i),
            .is_end = false,
        };
    }
    return null;
}

fn set_shdr_field(self: *Modder, index: RangeIndex, val: u64, comptime field_name: []const u8, file: anytype) !void {
    if (index >= self.header.shnum) return Error.OutOfBoundField;
    try file.seekTo(self.header.shoff + self.header.shentsize * index);
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
fn set_phdr_field(self: *Modder, index: RangeIndex, val: u64, comptime field_name: []const u8, file: anytype) !void {
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
    const aligns = self.ranges.items(.alignment);
    const offs = self.ranges.items(.off);
    const fileszs = self.ranges.items(.filesz);
    const index = self.off_to_range[self.top_to_off[top_idx]];

    const align_offset = (offs[index] + (aligns[index] - (size % aligns[index]))) % aligns[index]; // The target value for 'new_off % top_idx.align'
    const prev_idx = self.off_to_range[self.top_to_off[top_idx - 1]];
    const prev_off_end = offs[prev_idx] + fileszs[prev_idx];
    if (prev_off_end > offs[index]) return Error.IntersectingFileRanges;
    const new_offset = if (offs[index] > (size + prev_off_end))
        (offs[index] - size)
    else
        (prev_off_end + (if ((prev_off_end % aligns[index]) <= align_offset)
            (align_offset)
        else
            (aligns[index] + align_offset)) - (prev_off_end % aligns[index]));
    return new_offset;
}

fn shift_forward(self: *Modder, size: u64, start_top_idx: TopIndex, file: anytype) !void {
    const offs = self.ranges.items(.off);
    const fileszs = self.ranges.items(.filesz);
    const aligns = self.ranges.items(.alignment);

    var needed_size = size;
    var top_idx = start_top_idx;
    while (top_idx < self.top_to_off.len) : (top_idx += 1) {
        const off_range_index = self.top_to_off[top_idx];
        const range_index = self.off_to_range[off_range_index];
        const prev_off_range_index = self.top_to_off[top_idx - 1];
        const prev_range_index = self.off_to_range[prev_off_range_index];
        const existing_gap = offs[range_index] - (offs[prev_range_index] + fileszs[prev_range_index]);
        if (needed_size < existing_gap) break;
        needed_size -= existing_gap;
        // TODO: definetly the case that I should be looking at the maximum alignment of all contained ranges here.
        if ((aligns[range_index] != 0) and ((needed_size % aligns[range_index]) != 0)) {
            needed_size += aligns[range_index] - (needed_size % aligns[range_index]);
        }
        self.adjustments[top_idx - start_top_idx] = needed_size;
    }
    var i = top_idx - start_top_idx;
    while (i > 0) {
        i -= 1;
        const top_index = i + start_top_idx;
        const top_off_idx = self.top_to_off[top_index];
        const top_range_idx = self.off_to_range[top_off_idx];
        try shift.shift_forward(file, offs[top_range_idx], offs[top_range_idx] + fileszs[top_range_idx], self.adjustments[i]);
        const final_off_idx = if ((top_index + 1) == self.top_to_off.len) self.ranges.len else self.top_to_off[top_index + 1];
        for (top_off_idx..final_off_idx) |off_idx| {
            const index = self.off_to_range[off_idx];
            offs[index] += self.adjustments[i];
            try self.set_filerange_field(index, offs[index], .off, file);
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
            const temp = index - (self.header.shnum + 1);
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
    if (edge.top_idx == 0) return Error.CantExpandPhdr;
    const offs = self.ranges.items(.off);
    const addrs = self.ranges.items(.addr);
    const fileszs = self.ranges.items(.filesz);
    const memszs = self.ranges.items(.memsz);
    const idx = self.off_to_range[self.top_to_off[edge.top_idx]];
    // const shoff_top_idx = self.off_to_top_idx(self.header.shoff);

    const old_offset: u64 = offs[idx];
    const new_offset: u64 = if (edge.is_end) old_offset else try self.calc_new_off(edge.top_idx, size);
    const first_adjust = if (edge.is_end) size else if (new_offset < old_offset) size - (old_offset - new_offset) else size + (new_offset - old_offset);
    try self.shift_forward(first_adjust, edge.top_idx + 1, file);

    if (!edge.is_end) {
        const top_off_idx = self.top_to_off[edge.top_idx];
        const final_off_idx = if ((edge.top_idx + 1) == self.top_to_off.len) self.ranges.len else self.top_to_off[edge.top_idx + 1];

        // TODO: consider the following
        // if (shoff_top_idx == edge.top_idx) {
        //     try self.set_ehdr_field(self.header.shoff + new_offset + size - old_offset, "shoff", file);
        // }
        try shift.shift_forward(file, old_offset, old_offset + fileszs[idx], first_adjust);

        offs[idx] = new_offset;
        try self.set_filerange_field(idx, offs[idx], .off, file);

        for (top_off_idx + 1..final_off_idx) |off_idx| {
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
            offs[index] = offs[index] + first_adjust;
            try self.set_filerange_field(index, offs[index], .off, file);
            // }
        }
        addrs[idx] -= size;
        try self.set_filerange_field(idx, addrs[idx], .addr, file);
    }
    fileszs[idx] += size;
    memszs[idx] += size;
    // try self.set_filerange_field(idx, fileszs[idx], .filesz, file)
    // try self.set_filerange_field(idx, memszs[idx], .memsz, file)
    switch (self.range_type(idx)) {
        .ProgramHeader => {
            try self.set_phdr_field(idx - (self.header.shnum + 1), fileszs[idx], "p_filesz", file);
            try self.set_phdr_field(idx - (self.header.shnum + 1), memszs[idx], "p_memsz", file);
        },
        .SectionHeaderTable => {}, // NOTE: This very much does not make sense.
        .SectionHeader => {

            // NOTE: This kind of does not make sense.
            // TODO: consider what to do with a NOBITS section.
            try self.set_shdr_field(idx, fileszs[idx], "sh_size", file);
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
    const offs = self.ranges.items(.off);
    const fileszs = self.ranges.items(.filesz);
    const addrs = self.ranges.items(.addr);
    const memszs = self.ranges.items(.memsz);
    const aligns = self.ranges.items(.alignment);
    const phdr_top_idx = self.off_to_top_idx(self.header.phoff);
    const top_off_idx = self.top_to_off[phdr_top_idx];
    const top_range_idx = self.off_to_range[top_off_idx];

    var needed_size: u64 = self.header.phentsize;
    if ((aligns[top_range_idx] != 0) and ((needed_size % aligns[top_range_idx]) != 0)) {
        needed_size += aligns[top_range_idx] - (needed_size % aligns[top_range_idx]);
    }
    const final_off_idx = blk: {
        if ((phdr_top_idx + 1) == self.top_to_off.len) {
            break :blk self.ranges.len;
        } else {
            const post_off_idx = self.top_to_off[phdr_top_idx + 1];
            break :blk post_off_idx;
        }
    };

    const phdr_off_idx = std.sort.lowerBound(
        RangeIndex,
        self.off_to_range[top_off_idx..final_off_idx],
        CompareContext{ .self = self, .lhs = self.header.phoff + 1 },
        off_compareFn,
    ) - 1 + top_off_idx;
    const phdr_range_idx = self.off_to_range[phdr_off_idx];
    const phdr_addr_idx = self.range_to_addr[phdr_range_idx];
    const phdr_load_idx = self.addr_to_load[phdr_addr_idx];
    const phdr_is_contained = ((addrs[top_range_idx] + memszs[top_range_idx]) != (addrs[phdr_range_idx] + memszs[phdr_range_idx]));
    const have_forward_space = (addrs[top_range_idx] + memszs[top_range_idx] + needed_size) < addrs[self.addr_to_range[self.load_to_addr[phdr_load_idx + 1]]];
    const have_back_space = addrs[top_range_idx] > needed_size;
    if ((!have_back_space) and (phdr_is_contained or !have_forward_space)) return Error.NoSpaceToExtendPhdrTable;

    if ((offs[phdr_range_idx] + fileszs[phdr_range_idx]) != (self.header.phoff + self.header.phentsize * self.header.phnum)) {
        return Error.PhdrTablePhdrNotFound;
    }
    try self.shift_forward(needed_size, phdr_top_idx + 1, file);
    try shift.shift_forward(
        file,
        self.header.phoff + self.header.phentsize * self.header.phnum,
        offs[top_range_idx] + fileszs[top_range_idx],
        needed_size,
    );
    fileszs[top_range_idx] += needed_size;
    try self.set_filerange_field(top_range_idx, fileszs[top_range_idx], .filesz, file);
    memszs[top_range_idx] += needed_size;
    try self.set_filerange_field(top_range_idx, memszs[top_range_idx], .memsz, file);

    fileszs[phdr_range_idx] += self.header.phentsize;
    try self.set_filerange_field(phdr_range_idx, fileszs[phdr_range_idx], .filesz, file);
    memszs[phdr_range_idx] += self.header.phentsize;
    try self.set_filerange_field(phdr_range_idx, memszs[phdr_range_idx], .memsz, file);

    for (phdr_off_idx + 1..final_off_idx) |off_idx| {
        const index = self.off_to_range[off_idx];
        offs[index] += needed_size;
        try self.set_filerange_field(index, offs[index], .off, file);
    }

    if (!have_forward_space) {
        addrs[top_range_idx] -= needed_size;
        try self.set_filerange_field(top_range_idx, addrs[top_range_idx], .addr, file);
        addrs[phdr_range_idx] -= needed_size; // self.header.phentsize;
        try self.set_filerange_field(phdr_range_idx, addrs[phdr_range_idx], .addr, file);
        const prev_load_range_idx = self.addr_to_range[self.load_to_addr[phdr_load_idx + 1]];
        memszs[prev_load_range_idx] -= needed_size;
        try self.set_filerange_field(prev_load_range_idx, memszs[prev_load_range_idx], .memsz, file);
    }

    const last_off_range_idx = self.off_to_range[self.top_to_off[self.top_to_off.len - 1]];
    const max_off = offs[last_off_range_idx] + fileszs[last_off_range_idx];
    if (max_off != try file.getEndPos()) return Error.UnmappedRange;
    const last_addr_range_idx = self.addr_to_range[self.load_to_addr[self.load_to_addr.len - 1]];
    const max_addr = addrs[last_addr_range_idx] + memszs[last_addr_range_idx];
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
    self.off_to_range = (try gpa.realloc(self.off_to_range[0..self.ranges.len], self.ranges.len + 1)).ptr;
    self.off_to_range[self.ranges.len] = @intCast(self.ranges.len);
    self.addr_to_range = (try gpa.realloc(self.addr_to_range[0..self.ranges.len], self.ranges.len + 1)).ptr;
    self.addr_to_range[self.ranges.len] = @intCast(self.ranges.len);
    self.range_to_off = (try gpa.realloc(self.range_to_off[0..self.ranges.len], self.ranges.len + 1)).ptr;
    self.range_to_off[self.ranges.len] = @intCast(self.ranges.len);
    self.range_to_addr = (try gpa.realloc(self.range_to_addr[0..self.ranges.len], self.ranges.len + 1)).ptr;
    self.range_to_addr[self.ranges.len] = @intCast(self.ranges.len);
    self.addr_to_load = (try gpa.realloc(self.addr_to_load[0..self.ranges.len], self.ranges.len + 1)).ptr;
    self.addr_to_load[self.ranges.len] = @intCast(self.load_to_addr.len);
    self.adjustments = (try gpa.realloc(self.adjustments[0..self.top_to_off.len], self.top_to_off.len + 1)).ptr;
    self.top_to_off = try gpa.realloc(self.top_to_off, self.top_to_off.len + 1);
    self.top_to_off[self.top_to_off.len - 1] = @intCast(self.ranges.len);
    self.load_to_addr = try gpa.realloc(self.load_to_addr, self.load_to_addr.len + 1);
    self.load_to_addr[self.load_to_addr.len - 1] = @intCast(self.ranges.len);
    try self.ranges.append(gpa, .{
        .addr = max_addr + alignment_addend,
        .off = max_off,
        .flags = flags,
        .alignment = alignment,
        .filesz = size,
        .memsz = size,
    });
}

const CompareContext = struct {
    self: *const Modder,
    lhs: u64,
};

fn addr_compareFn(context: CompareContext, rhs: AddrIndex) std.math.Order {
    return std.math.order(context.lhs, context.self.ranges.items(.addr)[context.self.addr_to_range[rhs]]);
}

pub fn addr_to_off(self: *const Modder, addr: u64) !u64 {
    const offs = self.ranges.items(.off);
    const addrs = self.ranges.items(.addr);
    const fileszs = self.ranges.items(.filesz);
    const memszs = self.ranges.items(.memsz);
    const containnig_idx = try self.addr_to_idx(addr);
    if (addr >= (addrs[containnig_idx] + memszs[containnig_idx])) return Error.AddrNotMapped;
    const potenital_off = offs[containnig_idx] + addr - addrs[containnig_idx];
    if (potenital_off >= (offs[containnig_idx] + fileszs[containnig_idx])) return Error.NoMatchingOffset;
    return potenital_off;
}

fn addr_to_idx(self: *const Modder, addr: u64) !RangeIndex {
    const lower_bound = std.sort.lowerBound(AddrIndex, self.load_to_addr, CompareContext{ .self = self, .lhs = addr + 1 }, addr_compareFn);
    if (lower_bound == 0) return Error.AddrNotMapped;
    return self.addr_to_range[self.load_to_addr[lower_bound - 1]];
}

fn top_off_compareFn(context: CompareContext, rhs: OffIndex) std.math.Order {
    return std.math.order(context.lhs, context.self.ranges.items(.off)[context.self.off_to_range[rhs]]);
}

fn off_compareFn(context: CompareContext, rhs: RangeIndex) std.math.Order {
    return std.math.order(context.lhs, context.self.ranges.items(.off)[rhs]);
}

pub fn off_to_addr(self: *const Modder, off: u64) !u64 {
    const offs = self.ranges.items(.off);
    const addrs = self.ranges.items(.addr);
    const fileszs = self.ranges.items(.filesz);
    const memszs = self.ranges.items(.memsz);
    const containnig_idx = self.off_to_range[self.top_to_off[self.off_to_top_idx(off)]];
    if (!(off < (offs[containnig_idx] + fileszs[containnig_idx]))) return Error.OffsetNotLoaded;
    // NOTE: cant think of a case where the memsz will be smaller then the filesz (of a top level segment?).
    if (memszs[containnig_idx] < fileszs[containnig_idx]) return Error.FileszBiggerThenMemsz;
    return addrs[containnig_idx] + off - offs[containnig_idx];
}

/// return the offset of the start of the cave described by `cave` and `size`.
/// assumes that create_cave has been called with cave and size, and returned successfully.
pub fn cave_to_off(self: *const Modder, cave: SegEdge, size: u64) u64 {
    const idx = self.off_to_range[self.top_to_off[cave.top_idx]];
    return self.ranges.items(.off)[idx] + if (cave.is_end) self.ranges.items(.filesz)[idx] - size else 0;
}

fn off_to_top_idx(self: *const Modder, off: u64) TopIndex {
    return @intCast(std.sort.lowerBound(OffIndex, self.top_to_off, CompareContext{ .self = self, .lhs = off + 1 }, top_off_compareFn) - 1);
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
        const index = elf_modder.addr_to_range[load_range];
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
        for (elf_modder.addr_to_range[load_range..end]) |range_idx| {
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
}

test "create cave same output" {
    const test_src_path = "./tests/hello_world.zig";
    const test_with_cave_prefix = "./create_cave_same_output_elf";
    const native_compile_path = "./elf_cave_hello_world";
    const cwd: std.fs.Dir = std.fs.cwd();
    const optimzes = &.{ "ReleaseSmall", "ReleaseSafe", "ReleaseFast", "Debug" };
    const targets = &.{ "x86_64-linux", "x86-linux", "aarch64-linux", "arm-linux" };
    const qemus = &.{ "qemu-x86_64", "qemu-i386", "qemu-aarch64", "qemu-arm" };
    {
        const build_native_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-femit-bin=" ++ native_compile_path[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_native_result.stdout);
        defer std.testing.allocator.free(build_native_result.stderr);
        try std.testing.expect(build_native_result.term == .Exited);
    }
    const no_cave_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{native_compile_path},
    });
    defer std.testing.allocator.free(no_cave_result.stdout);
    defer std.testing.allocator.free(no_cave_result.stderr);
    try std.testing.expect(no_cave_result.term == .Exited);

    inline for (optimzes) |optimize| {
        inline for (targets, qemus) |target, qemu| {
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
                try std.testing.expect(no_cave_result.term == .Exited);
                try std.testing.expectEqual(cave_result.term.Exited, no_cave_result.term.Exited);
                try std.testing.expectEqualStrings(cave_result.stdout, no_cave_result.stdout);
                try std.testing.expectEqualStrings(cave_result.stderr, no_cave_result.stderr);
            }
        }
    }

    if (builtin.os.tag != .linux) {
        return error.SkipZigTest;
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
    if (builtin.os.tag != .linux) {
        error.SkipZigTest;
    }
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

    // check regular output.
    const no_cave_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_cave},
    });
    defer std.testing.allocator.free(no_cave_result.stdout);
    defer std.testing.allocator.free(no_cave_result.stderr);

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

    // check output with a cave
    const cave_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_cave},
    });
    defer std.testing.allocator.free(cave_result.stdout);
    defer std.testing.allocator.free(cave_result.stderr);
    try std.testing.expect(cave_result.term == .Exited);
    try std.testing.expect(no_cave_result.term == .Exited);
    try std.testing.expectEqual(cave_result.term.Exited, no_cave_result.term.Exited);
    try std.testing.expectEqualStrings(cave_result.stdout, no_cave_result.stdout);
    try std.testing.expectEqualStrings(cave_result.stderr, no_cave_result.stderr);
}
