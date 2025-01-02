const std = @import("std");
const native_endian = @import("builtin").target.cpu.arch.endian();
const utils = @import("utils.zig");
const elf = std.elf;

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
        (fileszs[lhs] > fileszs[rhs])));
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
    flags: utils.FileRangeFlags,
};

const FileRangeFields = std.meta.FieldEnum(FileRange);

pub const ElfModder: type = struct {
    header: elf.Header,
    ranges: std.MultiArrayList(FileRange),
    phdrs_count: usize,
    off_sort: [*]usize,
    addr_sort: [*]usize,
    range_to_off: [*]usize,
    range_to_addr: [*]usize,
    addr_to_top: [*]usize,
    // TODO: think if the following three should be slices or if one of them should be a slice and the rest many item pointers.
    top_offs: []usize,
    top_addrs: []usize,
    adjustments: []usize,
    parse_source: *std.io.StreamSource,

    const Self = @This();

    pub fn init(gpa: std.mem.Allocator, parse_source: *std.io.StreamSource) Error!Self {
        var header = try elf.Header.read(parse_source);
        var ranges = std.MultiArrayList(FileRange){};
        errdefer ranges.deinit(gpa);
        var phdrs_iter = header.program_header_iterator(parse_source);
        while (try phdrs_iter.next()) |phdr| {
            const flags: PFlags = @bitCast(phdr.p_flags);
            try ranges.append(gpa, FileRange{
                .off = phdr.p_offset,
                .filesz = phdr.p_filesz,
                .addr = phdr.p_vaddr,
                .memsz = phdr.p_memsz,
                .alignment = phdr.p_align,
                .flags = utils.FileRangeFlags{
                    .read = flags.PF_R,
                    .write = flags.PF_W,
                    .execute = flags.PF_X,
                },
            });
        }
        const phdrs_count = ranges.len;
        var shdrs_iter = header.section_header_iterator(parse_source);
        while (try shdrs_iter.next()) |shdr| {
            try ranges.append(gpa, FileRange{
                .off = shdr.sh_offset,
                .filesz = if ((shdr.sh_type & elf.SHT_NOBITS) != 0) 0 else shdr.sh_size,
                .addr = shdr.sh_addr,
                .memsz = shdr.sh_size,
                .alignment = shdr.sh_addralign,
                .flags = utils.FileRangeFlags{},
            });
        }
        // NOTE: we create an explict file range for the section header table to ensure that it wont be overriden.
        try ranges.append(gpa, FileRange{
            .off = header.shoff,
            .filesz = header.shentsize * header.shnum,
            .addr = 0,
            .memsz = 0,
            .alignment = 0,
            .flags = utils.FileRangeFlags{},
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
        var containing_index = off_sort[0];
        var containing_count: usize = 1;
        std.debug.assert(offs[containing_index] == 0);
        for (off_sort[1..]) |index| {
            const off = offs[index];
            if (off < (offs[containing_index] + fileszs[containing_index])) {
                std.debug.assert((off + fileszs[index]) <= (offs[containing_index] + fileszs[containing_index]));
            } else {
                containing_index = index;
                containing_count += 1;
            }
        }
        const top_offs = try gpa.alloc(usize, containing_count);
        errdefer gpa.free(top_offs);
        containing_count = 0;
        containing_index = off_sort[0];
        top_offs[containing_count] = 0;
        containing_count += 1;
        for (off_sort[1..], 1..) |index, i| {
            const off = offs[index];
            if (off >= (offs[containing_index] + fileszs[containing_index])) {
                containing_index = index;
                top_offs[containing_count] = i;
                containing_count += 1;
            }
        }
        const addrs = ranges.items(FileRangeFields.addr);
        const memszs = ranges.items(FileRangeFields.memsz);
        containing_index = addr_sort[0];
        containing_count = 1;
        std.debug.assert(addrs[containing_index] == 0);
        for (addr_sort[1..]) |index| {
            const addr = addrs[index];
            if (addr < (addrs[containing_index] + memszs[containing_index])) {
                std.debug.assert((addr + memszs[index]) <= (addrs[containing_index] + memszs[containing_index]));
            } else {
                containing_index = index;
                containing_count += 1;
            }
        }
        const top_addrs = try gpa.alloc(usize, containing_count);
        errdefer gpa.free(top_addrs);
        containing_count = 0;
        containing_index = addr_sort[0];
        top_addrs[containing_count] = 0;
        containing_count += 1;
        for (addr_sort[1..], 1..) |index, i| {
            const addr = addrs[index];
            if (addr >= (addrs[containing_index] + memszs[containing_index])) {
                containing_index = index;
                top_addrs[containing_count] = i;
                containing_count += 1;
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

        return Self{
            .header = header,
            .ranges = ranges,
            .phdrs_count = phdrs_count,
            .off_sort = off_sort.ptr,
            .addr_sort = addr_sort.ptr,
            .range_to_off = range_to_off.ptr,
            .range_to_addr = range_to_addr.ptr,
            .addr_to_top = addr_to_top.ptr,
            .top_offs = top_offs,
            .top_addrs = top_addrs,
            .adjustments = try gpa.alloc(usize, containing_count),
            .parse_source = parse_source,
        };
    }

    pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
        gpa.free(self.off_sort[0..self.ranges.len]);
        gpa.free(self.addr_sort[0..self.ranges.len]);
        gpa.free(self.range_to_off[0..self.ranges.len]);
        gpa.free(self.range_to_addr[0..self.ranges.len]);
        gpa.free(self.addr_to_top[0..self.ranges.len]);
        gpa.free(self.top_offs);
        gpa.free(self.top_addrs);
        gpa.free(self.adjustments);
        self.ranges.deinit(gpa);
    }

    // Get an identifier for the location within the file where additional data could be inserted.
    pub fn get_cave_option(self: *const Self, wanted_size: u64, flags: utils.FileRangeFlags) Error!?SegEdge {
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

    fn set_shdr_field(self: *Self, index: usize, val: u64, comptime field_name: []const u8) Error!void {
        try self.parse_source.seekTo(self.header.shoff + self.header.shentsize * index);
        if (self.header.is_64) {
            const T = std.meta.fieldInfo(elf.Elf64_Shdr, @field(Shdr64Fields, field_name)).type;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try self.parse_source.seekBy(@offsetOf(elf.Elf64_Shdr, field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.assert(try self.parse_source.write(&temp2) == @sizeOf(T));
        } else {
            const T = std.meta.fieldInfo(elf.Elf32_Shdr, @field(Shdr32Fields, field_name)).type;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try self.parse_source.seekBy(@offsetOf(elf.Elf32_Shdr, field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.assert(try self.parse_source.write(&temp2) == @sizeOf(T));
        }
        // self.shdrs.items(@field(Shdr64Fields, field_name))[index] = @intCast(val);
    }

    fn set_ehdr_field(self: *Self, val: u64, comptime field_name: []const u8) Error!void {
        const native_field_name = "e_" ++ field_name;
        try self.parse_source.seekTo(0);
        if (self.header.is_64) {
            const T = std.meta.fieldInfo(elf.Elf64_Ehdr, @field(Ehdr64Fields, native_field_name)).type;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try self.parse_source.seekBy(@offsetOf(elf.Elf64_Ehdr, native_field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.assert(try self.parse_source.write(&temp2) == @sizeOf(T));
        } else {
            const T = std.meta.fieldInfo(elf.Elf32_Ehdr, @field(Ehdr32Fields, native_field_name)).type;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try self.parse_source.seekBy(@offsetOf(elf.Elf32_Ehdr, native_field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.assert(try self.parse_source.write(&temp2) == @sizeOf(T));
        }
        @field(self.header, field_name) = @intCast(val);
    }

    // NOTE: field changes must NOT change the memory order or offset order!
    // TODO: consider what to do when setting the segment which holds the phdrtable itself.
    fn set_phdr_field(self: *Self, index: usize, val: u64, comptime field_name: []const u8) Error!void {
        try self.parse_source.seekTo(self.header.phoff + self.header.phentsize * index);
        if (self.header.is_64) {
            const T = std.meta.fieldInfo(elf.Elf64_Phdr, @field(Phdr64Fields, field_name)).type;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try self.parse_source.seekBy(@offsetOf(elf.Elf64_Phdr, field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.assert(try self.parse_source.write(&temp2) == @sizeOf(T));
        } else {
            const T = std.meta.fieldInfo(elf.Elf32_Phdr, @field(Phdr32Fields, field_name)).type;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try self.parse_source.seekBy(@offsetOf(elf.Elf32_Phdr, field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.assert(try self.parse_source.write(&temp2) == @sizeOf(T));
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
    pub fn create_cave(self: *Self, size: u64, edge: SegEdge) Error!void {
        // NOTE: moving around the pheader table sounds like a bad idea.
        std.debug.assert(edge.top_idx != 0);
        const aligns = self.ranges.items(FileRangeFields.alignment);
        const offs = self.ranges.items(FileRangeFields.off);
        const addrs = self.ranges.items(FileRangeFields.addr);
        const fileszs = self.ranges.items(FileRangeFields.filesz);
        const memszs = self.ranges.items(FileRangeFields.memsz);
        const idx = self.off_sort[self.top_offs[edge.top_idx]];
        const shoff_top_idx = self.off_to_top_idx(self.header.shoff);

        const new_offset: u64 = if (edge.is_end) offs[idx] else self.calc_new_offset(edge.top_idx, size);
        const first_adjust = if (edge.is_end) size else if (new_offset < offs[idx]) size - (offs[idx] - new_offset) else size + (new_offset - offs[idx]);
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
        if (shoff_top_idx > edge.top_idx) {
            try self.set_ehdr_field(self.header.shoff + self.adjustments[shoff_top_idx - (edge.top_idx + 1)], "shoff");
        }
        var i = top_idx - (edge.top_idx + 1);
        while (i > 0) {
            i -= 1;
            const top_index = i + edge.top_idx + 1;
            const top_off_idx = self.top_offs[top_index];
            const top_range_idx = self.off_sort[top_off_idx];
            try utils.shift_forward(self.parse_source, offs[top_range_idx], offs[top_range_idx] + fileszs[top_range_idx], self.adjustments[i]);
            const final_off_idx = if ((top_index + 1) == self.top_offs.len) self.ranges.len else self.top_offs[top_index + 1];
            for (top_off_idx..final_off_idx) |off_idx| {
                const index = self.off_sort[off_idx];
                if (index < self.phdrs_count) {
                    try self.set_phdr_field(index, offs[index] + self.adjustments[i], "p_offset");
                } else {
                    try self.set_shdr_field(index - self.phdrs_count, offs[index] + self.adjustments[i], "sh_offset");
                }
                offs[index] += self.adjustments[i];
            }
        }

        if (!edge.is_end) {
            const top_off_idx = self.top_offs[edge.top_idx];
            const final_off_idx = if ((edge.top_idx + 1) == self.top_offs.len) self.ranges.len else self.top_offs[edge.top_idx + 1];
            if (shoff_top_idx == edge.top_idx) {
                try self.set_ehdr_field(self.header.shoff + new_offset + size - offs[idx], "shoff");
            }
            try utils.shift_forward(self.parse_source, offs[idx], offs[idx] + fileszs[idx], new_offset + size - offs[idx]);
            for (top_off_idx..final_off_idx) |off_idx| {
                const index = self.off_sort[off_idx];
                // TODO: consider the following:
                //
                // if (offs[index] == offs[top_range_idx]) {
                //     if (index < self.phdrs_count) {
                //         try self.set_phdr_field(index, fileszs[index] + size, "p_filesz");
                //         try self.set_phdr_field(index, fileszs[index] + size, "p_memsz");
                //         try self.set_phdr_field(index, addrs[index] - size, "p_vaddr");
                //         try self.set_phdr_field(index, addrs[index] - size, "p_paddr");
                //         try self.set_phdr_field(index, new_offset, "p_offset");
                //     } else {
                //         try self.set_shdr_field(index - self.phdrs_count, fileszs[index] + size, "sh_size");
                //         try self.set_shdr_field(index - self.phdrs_count, addrs[index] - size, "sh_addr");
                //         try self.set_shdr_field(index - self.phdrs_count, new_offset, "sh_offset");
                //     }
                //     fileszs[index] += size;
                //     addrs[index] -= size;
                //     offs[index] = new_offset;
                // } else {
                offs[index] = new_offset + offs[index] - offs[idx];
                if (index < self.phdrs_count) {
                    try self.set_phdr_field(index, offs[index], "p_offset");
                } else {
                    try self.set_shdr_field(index - self.phdrs_count, offs[index], "sh_offset");
                }
                // }
            }
            if (idx < self.phdrs_count) {
                try self.set_phdr_field(idx, addrs[idx] - size, "p_vaddr");
                try self.set_phdr_field(idx, addrs[idx] - size, "p_paddr");
            } else {
                // TODO: consider what to do with a NOBITS section.
                try self.set_shdr_field(idx, addrs[idx] - size, "sh_addr");
            }
            addrs[idx] -= size;
        }
        if (idx < self.phdrs_count) {
            try self.set_phdr_field(idx, fileszs[idx] + size, "p_filesz");
            try self.set_phdr_field(idx, memszs[idx] + size, "p_memsz");
        } else {
            // TODO: consider what to do with a NOBITS section.
            try self.set_shdr_field(idx, fileszs[idx] + size, "sh_size");
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

test "create cave same output" {
    // NOTE: technically I could build the binary from source but I am unsure of a way to ensure that it will result in the exact same binary each time. (which would make the test flaky, since it might be that there is no viable code cave.).
    const test_path = "./tests/hello_world";
    const test_with_cave = "./create_cave_same_output_elf";
    const cwd: std.fs.Dir = std.fs.cwd();
    try cwd.copyFile(test_path, cwd, test_with_cave, .{});

    // check regular output.
    const no_cave_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_cave},
    });
    defer std.testing.allocator.free(no_cave_result.stdout);
    defer std.testing.allocator.free(no_cave_result.stderr);

    // create cave.
    // NOTE: need to put this in a block since the file must be closed before the next process can execute.
    {
        var f = try cwd.openFile(test_with_cave, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        const wanted_size = 0xfff;
        var elf_modder: ElfModder = try ElfModder.init(std.testing.allocator, &stream);
        defer elf_modder.deinit(std.testing.allocator);
        const option = (try elf_modder.get_cave_option(wanted_size, utils.FileRangeFlags{ .execute = true, .read = true })) orelse return error.NoCaveOption;
        try elf_modder.create_cave(wanted_size, option);
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
