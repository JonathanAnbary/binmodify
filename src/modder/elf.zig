const std = @import("std");
const elf = std.elf;

const native_endian = @import("builtin").target.cpu.arch.endian();
const builtin = @import("builtin");

const shift = @import("../shift.zig");
const common = @import("common.zig");

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
    OverlappingFileRanges,
} || ElfError || std.io.StreamSource.ReadError || std.io.StreamSource.WriteError || std.io.StreamSource.SeekError || std.io.StreamSource.GetSeekPosError;

pub const SegEdge: type = struct {
    top_idx: usize,
    is_end: bool,
};

const Phdr64Fields = std.meta.FieldEnum(elf.Elf64_Phdr);
const Phdr32Fields = std.meta.FieldEnum(elf.Elf32_Phdr);

const Shdr64Fields = std.meta.FieldEnum(elf.Elf64_Shdr);
const Shdr32Fields = std.meta.FieldEnum(elf.Elf32_Shdr);

const Ehdr64Fields = std.meta.FieldEnum(elf.Elf64_Ehdr);
const Ehdr32Fields = std.meta.FieldEnum(elf.Elf32_Ehdr);

fn off_lessThanFn(ranges: *std.MultiArrayList(FileRange), lhs: usize, rhs: usize) bool {
    const offs = ranges.items(FileRangeFields.off);
    const fileszs = ranges.items(FileRangeFields.filesz);
    return ((offs[lhs] < offs[rhs]) or
        ((offs[lhs] == offs[rhs]) and
        (fileszs[lhs] > fileszs[rhs])) or
        ((offs[lhs] == offs[rhs]) and
        (fileszs[lhs] == fileszs[rhs]) and
        (lhs < rhs)));
}

// TODO: consider if this should have a similar logic, where segments which "contain" other segments come first.
fn addr_lessThanFn(ranges: *std.MultiArrayList(FileRange), lhs: usize, rhs: usize) bool {
    const addrs = ranges.items(FileRangeFields.addr);
    return addrs[lhs] < addrs[rhs];
}

fn sec_offset_lessThanFn(shdrs: *std.MultiArrayList(elf.Elf64_Shdr), lhs: usize, rhs: usize) bool {
    return (shdrs.items(Shdr64Fields.sh_offset)[lhs] < shdrs.items(Shdr64Fields.sh_offset)[rhs]);
}

const FileRange: type = struct {
    off: u64,
    filesz: u64,
    addr: u64,
    memsz: u64,
    alignment: u64,
    flags: common.FileRangeFlags,
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

const FileRangeFields = std.meta.FieldEnum(FileRange);

pub const Modder: type = struct {
    header: PartialHeader,
    ranges: std.MultiArrayList(FileRange),
    off_sort: [*]usize,
    addr_sort: [*]usize,
    range_to_off: [*]usize,
    range_to_addr: [*]usize,
    addr_to_top: [*]usize,
    top_offs: []usize,
    adjustments: [*]usize,
    top_addrs: []usize,

    const Self = @This();

    pub fn init(gpa: std.mem.Allocator, header: *const elf.Header, parse_source: anytype) Error!Self {
        var ranges = std.MultiArrayList(FileRange){};
        errdefer ranges.deinit(gpa);
        // + 1 for the sechdr table which appears to not be contained in any section/segment.
        try ranges.ensureTotalCapacity(gpa, header.phnum + header.shnum + 1);
        var phdrs_iter = header.program_header_iterator(parse_source);
        while (try phdrs_iter.next()) |phdr| {
            const flags: PFlags = @bitCast(phdr.p_flags);
            ranges.appendAssumeCapacity(FileRange{
                .off = phdr.p_offset,
                .filesz = phdr.p_filesz,
                .addr = phdr.p_vaddr,
                .memsz = phdr.p_memsz,
                .alignment = phdr.p_align,
                .flags = common.FileRangeFlags{
                    .read = flags.PF_R,
                    .write = flags.PF_W,
                    .execute = flags.PF_X,
                },
            });
        }
        var shdrs_iter = header.section_header_iterator(parse_source);
        while (try shdrs_iter.next()) |shdr| {
            ranges.appendAssumeCapacity(FileRange{
                .off = shdr.sh_offset,
                .filesz = if ((shdr.sh_type & elf.SHT_NOBITS) != 0) 0 else shdr.sh_size,
                .addr = shdr.sh_addr,
                .memsz = shdr.sh_size,
                .alignment = shdr.sh_addralign,
                .flags = common.FileRangeFlags{},
            });
        }
        // TODO: consider first checking if its already contained in a range.
        // NOTE: we create an explict file range for the section header table to ensure that it wont be overriden.
        ranges.appendAssumeCapacity(FileRange{
            .off = header.shoff,
            .filesz = header.shentsize * header.shnum,
            .addr = 0,
            .memsz = 0,
            .alignment = 0,
            .flags = common.FileRangeFlags{},
        });
        var off_sort = try gpa.alloc(usize, ranges.len);
        errdefer gpa.free(off_sort[0..ranges.len]);
        var addr_sort = try gpa.alloc(usize, ranges.len);
        errdefer gpa.free(addr_sort[0..ranges.len]);
        for (0..ranges.len) |i| {
            off_sort[i] = i;
            addr_sort[i] = i;
        }
        std.sort.pdq(usize, off_sort, &ranges, off_lessThanFn);
        std.sort.pdq(usize, addr_sort, &ranges, addr_lessThanFn);
        const range_to_off = try gpa.alloc(usize, ranges.len);
        errdefer gpa.free(range_to_off[0..ranges.len]);
        const range_to_addr = try gpa.alloc(usize, ranges.len);
        errdefer gpa.free(range_to_addr[0..ranges.len]);
        for (off_sort, addr_sort, 0..) |off_idx, addr_idx, idx| {
            range_to_off[off_idx] = idx;
            range_to_addr[addr_idx] = idx;
        }
        const offs = ranges.items(FileRangeFields.off);
        const fileszs = ranges.items(FileRangeFields.filesz);
        std.debug.assert(ranges.len != 0);
        var off_containing_index = off_sort[0];
        var off_containing_count: usize = 1;
        std.debug.assert(offs[off_containing_index] == 0);
        for (off_sort[1..]) |index| {
            const off = offs[index];
            if (off >= (offs[off_containing_index] + fileszs[off_containing_index])) {
                off_containing_index = index;
                off_containing_count += 1;
            } else {
                if ((off + fileszs[index]) > (offs[off_containing_index] + fileszs[off_containing_index])) return Error.OverlappingFileRanges;
            }
        }
        const top_offs = try gpa.alloc(usize, off_containing_count);
        errdefer gpa.free(top_offs);
        off_containing_count = 0;
        off_containing_index = off_sort[0];
        top_offs[off_containing_count] = 0;
        off_containing_count += 1;
        for (off_sort[1..], 1..) |index, i| {
            const off = offs[index];
            if (off >= (offs[off_containing_index] + fileszs[off_containing_index])) {
                off_containing_index = index;
                top_offs[off_containing_count] = i;
                off_containing_count += 1;
            }
        }
        const addrs = ranges.items(FileRangeFields.addr);
        const memszs = ranges.items(FileRangeFields.memsz);
        var addr_containing_index = addr_sort[0];
        var addr_containing_count: usize = 1;
        std.debug.assert(addrs[addr_containing_index] == 0);
        for (addr_sort[1..]) |index| {
            const addr = addrs[index];
            if (addr < (addrs[addr_containing_index] + memszs[addr_containing_index])) {
                std.debug.assert((addr + memszs[index]) <= (addrs[addr_containing_index] + memszs[addr_containing_index]));
            } else {
                addr_containing_index = index;
                addr_containing_count += 1;
            }
        }
        const top_addrs = try gpa.alloc(usize, addr_containing_count);
        errdefer gpa.free(top_addrs);
        addr_containing_count = 0;
        addr_containing_index = addr_sort[0];
        top_addrs[addr_containing_count] = 0;
        addr_containing_count += 1;
        for (addr_sort[1..], 1..) |index, i| {
            const addr = addrs[index];
            if (addr >= (addrs[addr_containing_index] + memszs[addr_containing_index])) {
                addr_containing_index = index;
                top_addrs[addr_containing_count] = i;
                addr_containing_count += 1;
            }
        }

        const addr_to_top = try gpa.alloc(usize, ranges.len);
        errdefer gpa.free(addr_to_top[0..ranges.len]);
        var prev_top = top_addrs[0];
        for (top_addrs[1..], 1..) |top_addr, top_idx| {
            for (prev_top..top_addr) |addr_idx| {
                addr_to_top[addr_idx] = top_idx - 1;
            }
            prev_top = top_addr;
        }

        const temp = Self{
            .header = .{
                .is_64 = header.is_64,
                .endian = header.endian,
                .entry = header.entry,
                .phoff = header.phoff,
                .shoff = header.shoff,
                .phentsize = header.phentsize,
                .phnum = header.phnum,
                .shentsize = header.shentsize,
                .shnum = header.shnum,
            },
            .ranges = ranges,
            .off_sort = off_sort.ptr,
            .addr_sort = addr_sort.ptr,
            .range_to_off = range_to_off.ptr,
            .range_to_addr = range_to_addr.ptr,
            .addr_to_top = addr_to_top.ptr,
            .top_offs = top_offs,
            .adjustments = (try gpa.alloc(usize, off_containing_count)).ptr,
            .top_addrs = top_addrs,
        };

        return temp;
    }

    pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
        gpa.free(self.adjustments[0..self.top_offs.len]);
        gpa.free(self.addr_to_top[0..self.ranges.len]);
        gpa.free(self.top_addrs);
        gpa.free(self.top_offs);
        gpa.free(self.range_to_addr[0..self.ranges.len]);
        gpa.free(self.range_to_off[0..self.ranges.len]);
        gpa.free(self.addr_sort[0..self.ranges.len]);
        gpa.free(self.off_sort[0..self.ranges.len]);
        self.ranges.deinit(gpa);
    }

    // Get an identifier for the location within the file where additional data could be inserted.
    pub fn get_cave_option(self: *const Self, wanted_size: u64, flags: common.FileRangeFlags) Error!?SegEdge {
        const flagss = self.ranges.items(FileRangeFields.flags);
        const addrs = self.ranges.items(FileRangeFields.addr);
        const memszs = self.ranges.items(FileRangeFields.memsz);
        var i = self.top_offs.len;
        while (i > 0) {
            i -= 1;
            const off_idx = self.top_offs[i];
            const range_idx = self.off_sort[off_idx];
            const addr_idx = self.range_to_addr[range_idx];
            const top_addr_idx = self.addr_to_top[addr_idx];
            if (flagss[range_idx] != flags) continue;
            // NOTE: this assumes you dont have an upper bound on possible memory address.
            if ((addr_idx == (self.ranges.len - 1)) or
                ((addrs[range_idx] + memszs[range_idx] + wanted_size) < addrs[self.addr_sort[self.top_addrs[top_addr_idx + 1]]])) return SegEdge{
                .top_idx = i,
                .is_end = true,
            };
            const prev_top_seg_idx = self.addr_sort[self.top_addrs[top_addr_idx - 1]];
            const prev_seg_mem_bound = (if (addr_idx == 0) 0 else (addrs[prev_top_seg_idx] + memszs[prev_top_seg_idx]));
            if (addrs[range_idx] > (wanted_size + prev_seg_mem_bound)) return SegEdge{
                .top_idx = i,
                .is_end = false,
            };
        }
        return null;
    }

    fn set_shdr_field(self: *Self, index: usize, val: u64, comptime field_name: []const u8, parse_source: anytype) Error!void {
        try parse_source.seekTo(self.header.shoff + self.header.shentsize * index);
        if (self.header.is_64) {
            const T = std.meta.fieldInfo(elf.Elf64_Shdr, @field(Shdr64Fields, field_name)).type;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try parse_source.seekBy(@offsetOf(elf.Elf64_Shdr, field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.assert(try parse_source.write(&temp2) == @sizeOf(T));
        } else {
            const T = std.meta.fieldInfo(elf.Elf32_Shdr, @field(Shdr32Fields, field_name)).type;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try parse_source.seekBy(@offsetOf(elf.Elf32_Shdr, field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.assert(try parse_source.write(&temp2) == @sizeOf(T));
        }
        // self.shdrs.items(@field(Shdr64Fields, field_name))[index] = @intCast(val);
    }

    fn set_ehdr_field(self: *Self, val: u64, comptime field_name: []const u8, parse_source: anytype) Error!void {
        const native_field_name = "e_" ++ field_name;
        try parse_source.seekTo(0);
        if (self.header.is_64) {
            const T = std.meta.fieldInfo(elf.Elf64_Ehdr, @field(Ehdr64Fields, native_field_name)).type;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try parse_source.seekBy(@offsetOf(elf.Elf64_Ehdr, native_field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.assert(try parse_source.write(&temp2) == @sizeOf(T));
        } else {
            const T = std.meta.fieldInfo(elf.Elf32_Ehdr, @field(Ehdr32Fields, native_field_name)).type;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try parse_source.seekBy(@offsetOf(elf.Elf32_Ehdr, native_field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.assert(try parse_source.write(&temp2) == @sizeOf(T));
        }
        @field(self.header, field_name) = @intCast(val);
    }

    // NOTE: field changes must NOT change the memory order or offset order!
    // TODO: consider what to do when setting the segment which holds the phdrtable itself.
    fn set_phdr_field(self: *Self, index: usize, val: u64, comptime field_name: []const u8, parse_source: anytype) Error!void {
        try parse_source.seekTo(self.header.phoff + self.header.phentsize * index);
        if (self.header.is_64) {
            const T = std.meta.fieldInfo(elf.Elf64_Phdr, @field(Phdr64Fields, field_name)).type;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try parse_source.seekBy(@offsetOf(elf.Elf64_Phdr, field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.assert(try parse_source.write(&temp2) == @sizeOf(T));
        } else {
            const T = std.meta.fieldInfo(elf.Elf32_Phdr, @field(Phdr32Fields, field_name)).type;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try parse_source.seekBy(@offsetOf(elf.Elf32_Phdr, field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.assert(try parse_source.write(&temp2) == @sizeOf(T));
        }
        // self.phdrs.items(@field(Phdr64Fields, field_name))[index] = @intCast(val);
    }

    fn calc_new_offset(self: *const Self, top_idx: usize, size: u64) u64 {
        const aligns = self.ranges.items(FileRangeFields.alignment);
        const offs = self.ranges.items(FileRangeFields.off);
        const fileszs = self.ranges.items(FileRangeFields.filesz);
        const index = self.off_sort[self.top_offs[top_idx]];

        // TODO: add a check first for the case of an ending edge in which there already exists a large enough gap.
        // and for the case of a start edge whith enough space from the previous segment offset.
        const align_offset = (offs[index] + (aligns[index] - (size % aligns[index]))) % aligns[index];
        const temp = self.off_sort[self.top_offs[top_idx - 1]];
        const prev_off_end = offs[temp] + fileszs[temp];
        std.debug.assert(prev_off_end <= offs[index]);
        const new_offset = if (offs[index] > (size + prev_off_end))
            (offs[index] - size)
        else
            (prev_off_end + (if ((prev_off_end % aligns[index]) <= align_offset)
                (align_offset)
            else
                (aligns[index] + align_offset)) - (prev_off_end % aligns[index]));
        return new_offset;
    }

    // TODO: consider what happens when the original filesz and memsz are unequal.
    pub fn create_cave(self: *Self, size: u64, edge: SegEdge, parse_source: anytype) Error!void {
        // NOTE: moving around the pheader table sounds like a bad idea.
        std.debug.assert(edge.top_idx != 0);
        const aligns = self.ranges.items(FileRangeFields.alignment);
        const offs = self.ranges.items(FileRangeFields.off);
        const addrs = self.ranges.items(FileRangeFields.addr);
        const fileszs = self.ranges.items(FileRangeFields.filesz);
        const memszs = self.ranges.items(FileRangeFields.memsz);
        const idx = self.off_sort[self.top_offs[edge.top_idx]];
        // const shoff_top_idx = self.off_to_top_idx(self.header.shoff);

        const old_offset: u64 = offs[idx];
        const new_offset: u64 = if (edge.is_end) old_offset else self.calc_new_offset(edge.top_idx, size);
        const first_adjust = if (edge.is_end) size else if (new_offset < old_offset) size - (old_offset - new_offset) else size + (new_offset - old_offset);
        var needed_size = first_adjust;

        var top_idx = edge.top_idx + 1;
        while (top_idx < self.top_offs.len) : (top_idx += 1) {
            const off_range_index = self.top_offs[top_idx];
            const range_index = self.off_sort[off_range_index];
            const prev_off_range_index = self.top_offs[top_idx - 1];
            const prev_range_index = self.off_sort[prev_off_range_index];
            const existing_gap = offs[range_index] - (offs[prev_range_index] + fileszs[prev_range_index]);
            if (needed_size < existing_gap) break;
            needed_size -= existing_gap;
            // TODO: might be the case that I should be looking at the maximum alignment of all contained ranges here.
            if ((aligns[range_index] != 0) and ((needed_size % aligns[range_index]) != 0)) needed_size += aligns[range_index] - (needed_size % aligns[range_index]);
            self.adjustments[top_idx - (edge.top_idx + 1)] = needed_size;
        }
        var i = top_idx - (edge.top_idx + 1);
        while (i > 0) {
            i -= 1;
            const top_index = i + edge.top_idx + 1;
            const top_off_idx = self.top_offs[top_index];
            const top_range_idx = self.off_sort[top_off_idx];
            try shift.shift_forward(parse_source, offs[top_range_idx], offs[top_range_idx] + fileszs[top_range_idx], self.adjustments[i]);
            const final_off_idx = if ((top_index + 1) == self.top_offs.len) self.ranges.len else self.top_offs[top_index + 1];
            for (top_off_idx..final_off_idx) |off_idx| {
                const index = self.off_sort[off_idx];
                if (index < self.header.phnum) {
                    try self.set_phdr_field(index, offs[index] + self.adjustments[i], "p_offset", parse_source);
                } else if (index < (self.header.phnum + self.header.shnum)) {
                    try self.set_shdr_field(index - self.header.phnum, offs[index] + self.adjustments[i], "sh_offset", parse_source);
                } else {
                    try self.set_ehdr_field(offs[index] + self.adjustments[i], "shoff", parse_source);
                }
                offs[index] += self.adjustments[i];
            }
        }

        if (!edge.is_end) {
            const top_off_idx = self.top_offs[edge.top_idx];
            const final_off_idx = if ((edge.top_idx + 1) == self.top_offs.len) self.ranges.len else self.top_offs[edge.top_idx + 1];

            // TODO: consider the following
            // if (shoff_top_idx == edge.top_idx) {
            //     try self.set_ehdr_field(self.header.shoff + new_offset + size - old_offset, "shoff", parse_source);
            // }
            try shift.shift_forward(parse_source, old_offset, old_offset + fileszs[idx], new_offset + size - old_offset);
            for (top_off_idx..final_off_idx) |off_idx| {
                const index = self.off_sort[off_idx];
                // TODO: consider the following:
                //
                // if (offs[index] == offs[top_range_idx]) {
                //     if (index < self.header.phnum) {
                //         try self.set_phdr_field(index, fileszs[index] + size, "p_filesz", parse_source);
                //         try self.set_phdr_field(index, fileszs[index] + size, "p_memsz", parse_source);
                //         try self.set_phdr_field(index, addrs[index] - size, "p_vaddr", parse_source);
                //         try self.set_phdr_field(index, addrs[index] - size, "p_paddr", parse_source);
                //         try self.set_phdr_field(index, new_offset, "p_offset");
                //     } else {
                //         try self.set_shdr_field(index - self.header.phnum, fileszs[index] + size, "sh_size", parse_source);
                //         try self.set_shdr_field(index - self.header.phnum, addrs[index] - size, "sh_addr", parse_source);
                //         try self.set_shdr_field(index - self.header.phnum, new_offset, "sh_offset", parse_source);
                //     }
                //     fileszs[index] += size;
                //     addrs[index] -= size;
                //     offs[index] = new_offset;
                // } else {
                offs[index] = new_offset + offs[index] - old_offset;
                if (index < self.header.phnum) {
                    try self.set_phdr_field(index, offs[index], "p_offset", parse_source);
                } else {
                    try self.set_shdr_field(index - self.header.phnum, offs[index], "sh_offset", parse_source);
                }
                // }
            }
            if (idx < self.header.phnum) {
                try self.set_phdr_field(idx, addrs[idx] - size, "p_vaddr", parse_source);
                try self.set_phdr_field(idx, addrs[idx] - size, "p_paddr", parse_source);
            } else {
                // TODO: consider what to do with a NOBITS section.
                try self.set_shdr_field(idx, addrs[idx] - size, "sh_addr", parse_source);
            }
            addrs[idx] -= size;
        }
        if (idx < self.header.phnum) {
            try self.set_phdr_field(idx, fileszs[idx] + size, "p_filesz", parse_source);
            try self.set_phdr_field(idx, memszs[idx] + size, "p_memsz", parse_source);
        } else {
            // TODO: consider what to do with a NOBITS section.
            try self.set_shdr_field(idx, fileszs[idx] + size, "sh_size", parse_source);
        }
        fileszs[idx] += size;
        memszs[idx] += size;

        // TODO: debug info?)
    }

    const CompareContext = struct {
        self: *const Self,
        lhs: u64,
    };

    fn addr_compareFn(context: CompareContext, rhs: usize) std.math.Order {
        return std.math.order(context.lhs, context.self.ranges.items(FileRangeFields.addr)[context.self.addr_sort[rhs]]);
    }

    pub fn addr_to_off(self: *const Self, addr: u64) Error!u64 {
        const offs = self.ranges.items(FileRangeFields.off);
        const addrs = self.ranges.items(FileRangeFields.addr);
        const fileszs = self.ranges.items(FileRangeFields.filesz);
        const memszs = self.ranges.items(FileRangeFields.memsz);
        const containnig_idx = self.addr_to_idx(addr);
        if (!(addr < (addrs[containnig_idx] + memszs[containnig_idx]))) return Error.AddrNotMapped;
        const potenital_off = offs[containnig_idx] + addr - addrs[containnig_idx];
        if (!(potenital_off < (offs[containnig_idx] + fileszs[containnig_idx]))) return Error.NoMatchingOffset;
        return potenital_off;
    }

    fn addr_to_idx(self: *const Self, addr: u64) usize {
        return self.addr_sort[self.top_addrs[std.sort.lowerBound(usize, self.top_addrs, CompareContext{ .self = self, .lhs = addr + 1 }, addr_compareFn) - 1]];
    }

    fn off_compareFn(context: CompareContext, rhs: usize) std.math.Order {
        return std.math.order(context.lhs, context.self.ranges.items(FileRangeFields.off)[context.self.off_sort[rhs]]);
    }

    pub fn off_to_addr(self: *const Self, off: u64) Error!u64 {
        const offs = self.ranges.items(FileRangeFields.off);
        const addrs = self.ranges.items(FileRangeFields.addr);
        const fileszs = self.ranges.items(FileRangeFields.filesz);
        const memszs = self.ranges.items(FileRangeFields.memsz);
        const containnig_idx = self.off_sort[self.top_offs[self.off_to_top_idx(off)]];
        if (!(off < (offs[containnig_idx] + fileszs[containnig_idx]))) return Error.OffsetNotLoaded;
        // NOTE: cant think of a case where the memsz will be smaller then the filesz (of a top level segment?).
        std.debug.assert(memszs[containnig_idx] >= fileszs[containnig_idx]);
        return addrs[containnig_idx] + off - offs[containnig_idx];
    }

    pub fn cave_to_off(self: Self, cave: SegEdge, size: u64) u64 {
        const idx = self.off_sort[self.top_offs[cave.top_idx]];
        return self.ranges.items(FileRangeFields.off)[idx] + if (cave.is_end) self.ranges.items(FileRangeFields.filesz)[idx] - size else 0;
    }

    fn off_to_top_idx(self: *const Self, off: u64) usize {
        return std.sort.lowerBound(usize, self.top_offs, CompareContext{ .self = self, .lhs = off + 1 }, off_compareFn) - 1;
    }
};

fn print_modelf(elf_modder: Modder) void {
    const offs = elf_modder.ranges.items(FileRangeFields.off);
    std.debug.print("\n", .{});
    for (elf_modder.off_sort[0..elf_modder.ranges.len]) |idx| {
        std.debug.print("{X} - ", .{offs[idx]});
    }
    std.debug.print("\n", .{});
    std.debug.print("\n", .{});
    for (elf_modder.top_offs) |idx| {
        std.debug.print("{} - ", .{idx});
    }
    std.debug.print("\n", .{});

    std.debug.print("\nfile ranges:\n", .{});
    for (elf_modder.top_offs, 0..) |top_off, i| {
        const index = elf_modder.off_sort[top_off];
        var print_index: usize = undefined;
        var name: [*:0]const u8 = undefined;
        if (index < elf_modder.header.phnum) {
            name = "phdr";
            print_index = index;
        } else if (index < (elf_modder.header.phnum + elf_modder.header.shnum)) {
            name = "shdr";
            print_index = index - elf_modder.header.phnum;
        } else {
            name = "probably_shdr_table";
            print_index = index - elf_modder.header.phnum - elf_modder.header.shnum;
        }
        std.debug.print("top = {s} {} {X}:\n", .{
            name,
            print_index,
            offs[index],
        });
        const end = if ((i + 1) == elf_modder.top_offs.len) elf_modder.ranges.len else elf_modder.top_offs[i + 1];
        for (elf_modder.off_sort[top_off..end]) |range_idx| {
            if (range_idx < elf_modder.header.phnum) {
                name = "phdr";
                print_index = range_idx;
            } else if (range_idx < (elf_modder.header.phnum + elf_modder.header.shnum)) {
                name = "shdr";
                print_index = range_idx - elf_modder.header.phnum;
            } else {
                name = "probably_shdr_table";
                print_index = range_idx - elf_modder.header.phnum - elf_modder.header.shnum;
            }
            std.debug.print("\t{s} {} {X}, ", .{
                name,
                print_index,
                offs[range_idx],
            });
        }
        std.debug.print("\n", .{});
    }
}

test "create cave same output" {
    if (builtin.os.tag != .linux) {
        error.SkipZigTest;
    }
    const test_src_path = "./tests/hello_world.zig";
    const test_with_cave = "./create_cave_same_output_elf";
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
        const header = try std.elf.Header.read(&stream);
        var elf_modder: Modder = try Modder.init(std.testing.allocator, &header, &stream);
        defer elf_modder.deinit(std.testing.allocator);
        const option = (try elf_modder.get_cave_option(wanted_size, common.FileRangeFlags{ .execute = true, .read = true })) orelse return error.NoCaveOption;
        try elf_modder.create_cave(wanted_size, option, &stream);
    }

    // check output with a cave
    const cave_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_cave},
    });
    defer std.testing.allocator.free(cave_result.stdout);
    defer std.testing.allocator.free(cave_result.stderr);
    try std.testing.expect(cave_result.term.Exited == no_cave_result.term.Exited);
    try std.testing.expectEqualStrings(cave_result.stdout, no_cave_result.stdout);
    try std.testing.expectEqualStrings(cave_result.stderr, no_cave_result.stderr);
}

test "corrupted elf (non containied overlapping ranges)" {
    if (builtin.os.tag != .linux) {
        error.SkipZigTest;
    }
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
    var stream = std.io.StreamSource{ .file = f };
    try stream.seekTo(0x98);
    const patch = std.mem.toBytes(@as(u64, 0xAF5));
    try std.testing.expectEqual(patch.len, try stream.write(&patch));
    const header = try std.elf.Header.read(&stream);
    try std.testing.expectError(Error.OverlappingFileRanges, Modder.init(std.testing.allocator, &header, &stream));
}

test "repeated cave expansion equal to single cave" {
    if (builtin.os.tag != .linux) {
        error.SkipZigTest;
    }
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
        var stream = std.io.StreamSource{ .file = f_repeated };
        const header = try std.elf.Header.read(&stream);
        var elf_modder: Modder = try Modder.init(std.testing.allocator, &header, &stream);
        defer elf_modder.deinit(std.testing.allocator);
        var temp_sum: u32 = 0;
        for (0..10) |_| {
            const wanted_size = prng.random().intRangeAtMost(u8, 10, 100);
            const option = (try elf_modder.get_cave_option(wanted_size, common.FileRangeFlags{ .execute = true, .read = true })) orelse return error.NoCaveOption;
            try elf_modder.create_cave(wanted_size, option, &stream);
            temp_sum += wanted_size;
        }
        break :blk temp_sum;
    };
    var f_non_repeated = try cwd.openFile(test_with_non_repeated_cave, .{ .mode = .read_write });
    defer f_non_repeated.close();
    {
        var stream = std.io.StreamSource{ .file = f_non_repeated };
        const header = try std.elf.Header.read(&stream);
        var elf_modder: Modder = try Modder.init(std.testing.allocator, &header, &stream);
        defer elf_modder.deinit(std.testing.allocator);
        const option = (try elf_modder.get_cave_option(sum, common.FileRangeFlags{ .execute = true, .read = true })) orelse return error.NoCaveOption;
        try elf_modder.create_cave(sum, option, &stream);
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
