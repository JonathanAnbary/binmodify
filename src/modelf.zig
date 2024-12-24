const std = @import("std");
const native_endian = @import("builtin").target.cpu.arch.endian();

pub const PType: type = enum(u32) {
    PT_NULL = std.elf.PT_NULL,
    PT_LOAD = std.elf.PT_LOAD,
    PT_DYNAMIC = std.elf.PT_DYNAMIC,
    PT_INTERP = std.elf.PT_INTERP,
    PT_NOTE = std.elf.PT_NOTE,
    PT_SHLIB = std.elf.PT_SHLIB,
    PT_PHDR = std.elf.PT_PHDR,
    PT_TLS = std.elf.PT_TLS,
    PT_NUM = std.elf.PT_NUM,
    PT_LOOS = std.elf.PT_LOOS,
    PT_GNU_EH_FRAME = std.elf.PT_GNU_EH_FRAME,
    PT_GNU_STACK = std.elf.PT_GNU_STACK,
    PT_GNU_RELRO = std.elf.PT_GNU_RELRO,
    PT_LOSUNW = std.elf.PT_LOSUNW,
    // PT_SUNWBSS = std.elf.PT_SUNWBSS,
    PT_SUNWSTACK = std.elf.PT_SUNWSTACK,
    PT_HISUNW = std.elf.PT_HISUNW,
    // PT_HIOS = std.elf.PT_HIOS,
    PT_LOPROC = std.elf.PT_LOPROC,
    PT_HIPROC = std.elf.PT_HIPROC,
};

pub const PFlags: type = packed struct(u32) {
    PF_X: bool = false,
    PF_W: bool = false,
    PF_R: bool = false,
    _pad: u29 = 0,

    const Self = @This();

    comptime {
        std.debug.assert(std.elf.PF_X == @as(u32, @bitCast(Self{ .PF_X = true })));
        std.debug.assert(std.elf.PF_W == @as(u32, @bitCast(Self{ .PF_W = true })));
        std.debug.assert(std.elf.PF_R == @as(u32, @bitCast(Self{ .PF_R = true })));
    }
};

pub const ElfError = error{
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

fn shift_forward(stream: *std.io.StreamSource, start: u64, end: u64, amt: u64) Error!void {
    if ((start == end) or (amt == 0)) return;
    std.debug.assert(start < end);
    var buff: [1024]u8 = undefined;
    const shift_start: u64 = blk: {
        if (end < (start + amt)) {
            const temp = try stream.getEndPos();
            if ((start + amt) > temp) {
                try stream.seekTo(temp);
                try stream.writer().writeByteNTimes(0, start + amt - temp);
            }
            break :blk start;
        } else break :blk end - amt;
    };
    var pos = shift_start;
    while ((pos + buff.len) < end) : (pos += buff.len) {
        try stream.seekTo(pos);
        std.debug.assert(try stream.read(&buff) == buff.len);
        try stream.seekTo(pos + amt);
        std.debug.assert(try stream.write(&buff) == buff.len);
    }
    try stream.seekTo(pos);
    std.debug.assert(try stream.read(buff[0 .. end - pos]) == end - pos);
    try stream.seekTo(pos + amt);
    std.debug.assert(try stream.write(buff[0 .. end - pos]) == end - pos);
    pos = shift_start;
    while (pos > (start + buff.len)) : (pos -= buff.len) {
        try stream.seekTo(pos - buff.len);
        std.debug.assert(try stream.read(&buff) == buff.len);
        try stream.seekTo(pos - buff.len + amt);
        std.debug.assert(try stream.write(&buff) == buff.len);
    }
    try stream.seekTo(start);
    std.debug.assert(try stream.read(buff[0 .. pos - start]) == pos - start);
    try stream.seekTo(start + amt);
    std.debug.assert(try stream.write(buff[0 .. pos - start]) == pos - start);
}

test "test shift stream" {
    const start = 0;
    const end = 10;
    const shift = 3;
    var buf = "abcdefghijklmnopqrstuvwxyz".*;
    var expected = "abcabcdefghijnopqrstuvwxyz".*;
    @memcpy(expected[start + shift .. end + shift], buf[start..end]);
    var stream = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&buf) };
    try shift_forward(&stream, start, end, shift);
    try std.testing.expectEqualStrings(&expected, &buf);
    const start2 = 0;
    const end2 = 4432;
    const shift2 = 1543;
    var buf2 = [1]u8{'A'} ** 1024 ++ "\n".* ++ [1]u8{'B'} ** 1024 ++ "\n".* ++ [1]u8{'C'} ** 1024 ++ "\n".* ++ [1]u8{'D'} ** 1024 ++ "\n".* ++ [1]u8{'E'} ** 1024 ++ "\n".* ++ [1]u8{'F'} ** 1024 ++ "\n".*;
    var expected2 = [1]u8{'A'} ** 1024 ++ "\n".* ++ [1]u8{'B'} ** 1024 ++ "\n".* ++ [1]u8{'C'} ** 1024 ++ "\n".* ++ [1]u8{'D'} ** 1024 ++ "\n".* ++ [1]u8{'E'} ** 1024 ++ "\n".* ++ [1]u8{'F'} ** 1024 ++ "\n".*;
    @memcpy(expected2[start2 + shift2 .. end2 + shift2], buf2[start2..end2]);
    var stream2 = std.io.StreamSource{ .buffer = std.io.fixedBufferStream(&buf2) };
    try shift_forward(&stream2, start2, end2, shift2);
    try std.testing.expectEqualStrings(&expected2, &buf2);
}

pub const SegEdge: type = struct {
    top_idx: usize,
    is_end: bool,
};

pub const Phdr64Fields = std.meta.FieldEnum(std.elf.Elf64_Phdr);
pub const Phdr32Fields = std.meta.FieldEnum(std.elf.Elf32_Phdr);

pub const Shdr64Fields = std.meta.FieldEnum(std.elf.Elf64_Shdr);
pub const Shdr32Fields = std.meta.FieldEnum(std.elf.Elf32_Shdr);

fn offset_lessThanFn(phdrs: *std.MultiArrayList(std.elf.Elf64_Phdr), lhs: usize, rhs: usize) bool {
    return (phdrs.items(Phdr64Fields.p_offset)[lhs] < phdrs.items(Phdr64Fields.p_offset)[rhs]) or
        ((phdrs.items(Phdr64Fields.p_offset)[lhs] == phdrs.items(Phdr64Fields.p_offset)[rhs]) and
        (phdrs.items(Phdr64Fields.p_filesz)[lhs] > phdrs.items(Phdr64Fields.p_filesz)[rhs])) or
        ((phdrs.items(Phdr64Fields.p_offset)[lhs] == phdrs.items(Phdr64Fields.p_offset)[rhs]) and
        (phdrs.items(Phdr64Fields.p_filesz)[lhs] == phdrs.items(Phdr64Fields.p_filesz)[rhs]) and
        (@as(PType, @enumFromInt(phdrs.items(Phdr64Fields.p_type)[lhs])) == PType.PT_LOAD));
}

fn sec_offset_lessThanFn(shdrs: *std.MultiArrayList(std.elf.Elf64_Shdr), lhs: usize, rhs: usize) bool {
    return (shdrs.items(Shdr64Fields.sh_offset)[lhs] < shdrs.items(Shdr64Fields.sh_offset)[rhs]);
}

// TODO: consider if this should have a similar logic, where segments which "contain" other segments come first.
fn vaddr_lessThanFn(phdrs: *std.MultiArrayList(std.elf.Elf64_Phdr), lhs: usize, rhs: usize) bool {
    return phdrs.items(Phdr64Fields.p_vaddr)[lhs] < phdrs.items(Phdr64Fields.p_vaddr)[rhs];
}

pub const ElfModder: type = struct {
    header: std.elf.Header,
    phdrs: std.MultiArrayList(std.elf.Elf64_Phdr),
    phdrs_offset_order: []usize,
    phdrs_vaddr_order: []usize,
    // TODO: dont really need this, can just calculate it as I go by.
    top_off_segs: []usize,
    top_vaddr_segs: []usize,
    adjustments: []usize,
    shdrs: std.MultiArrayList(std.elf.Elf64_Shdr),
    shdrs_offset_order: []usize,
    parse_source: *std.io.StreamSource,

    const Self = @This();

    pub fn init(gpa: std.mem.Allocator, parse_source: *std.io.StreamSource) Error!Self {
        var header = try std.elf.Header.read(parse_source);
        var phdrs = std.MultiArrayList(std.elf.Elf64_Phdr){};
        var prog_headers_iter = header.program_header_iterator(parse_source);
        var count: usize = 0;
        while (try prog_headers_iter.next()) |prog_header| {
            count += 1;
            try phdrs.append(gpa, prog_header);
        }
        const offsets = phdrs.items(Phdr64Fields.p_offset);
        const fileszs = phdrs.items(Phdr64Fields.p_filesz);
        const vaddrs = phdrs.items(Phdr64Fields.p_vaddr);
        const memszs = phdrs.items(Phdr64Fields.p_memsz);
        var phdrs_offset_order = try gpa.alloc(usize, count);
        var phdrs_vaddr_order = try gpa.alloc(usize, count);
        for (0..count) |i| {
            phdrs_offset_order[i] = i;
            phdrs_vaddr_order[i] = i;
        }
        std.sort.pdq(usize, phdrs_offset_order, &phdrs, offset_lessThanFn);
        std.sort.pdq(usize, phdrs_vaddr_order, &phdrs, vaddr_lessThanFn);
        std.debug.assert(phdrs_offset_order.len != 0);
        var containing_index = phdrs_offset_order[0];
        var containing_count: usize = 1;
        std.debug.assert(offsets[containing_index] == 0);
        for (phdrs_offset_order[1..]) |index| {
            const offset = offsets[index];
            if (offset < (offsets[containing_index] + fileszs[containing_index])) {
                std.debug.assert((offset + fileszs[index]) <= (offsets[containing_index] + fileszs[containing_index]));
            } else {
                containing_index = index;
                containing_count += 1;
            }
        }
        const top_off_segs = try gpa.alloc(usize, containing_count);
        containing_count = 0;
        containing_index = phdrs_offset_order[0];
        top_off_segs[containing_count] = 0;
        containing_count += 1;
        for (phdrs_offset_order[1..], 1..) |index, i| {
            const offset = offsets[index];
            if (offset >= (offsets[containing_index] + fileszs[containing_index])) {
                containing_index = index;
                top_off_segs[containing_count] = i;
                containing_count += 1;
            }
        }
        containing_index = phdrs_vaddr_order[0];
        containing_count = 1;
        std.debug.assert(vaddrs[containing_index] == 0);
        for (phdrs_vaddr_order[1..]) |index| {
            const vaddr = vaddrs[index];
            if (vaddr < (vaddrs[containing_index] + memszs[containing_index])) {
                std.debug.assert((vaddr + memszs[index]) <= (vaddrs[containing_index] + memszs[containing_index]));
            } else {
                containing_index = index;
                containing_count += 1;
            }
        }
        const top_vaddr_segs = try gpa.alloc(usize, containing_count);
        containing_count = 0;
        containing_index = phdrs_vaddr_order[0];
        top_vaddr_segs[containing_count] = 0;
        containing_count += 1;
        for (phdrs_vaddr_order[1..], 1..) |index, i| {
            const vaddr = vaddrs[index];
            if (vaddr >= (vaddrs[containing_index] + memszs[containing_index])) {
                containing_index = index;
                top_vaddr_segs[containing_count] = i;
                containing_count += 1;
            }
        }

        var shdrs = std.MultiArrayList(std.elf.Elf64_Shdr){};
        var section_headers_iter = header.section_header_iterator(parse_source);
        count = 0;
        while (try section_headers_iter.next()) |section_header| {
            count += 1;
            try shdrs.append(gpa, section_header);
        }
        var shdrs_offset_order = try gpa.alloc(usize, count);
        for (0..count) |i| {
            shdrs_offset_order[i] = i;
        }
        std.sort.pdq(usize, shdrs_offset_order, &shdrs, sec_offset_lessThanFn);

        std.debug.print("phdrs = {any}\n", .{phdrs});
        std.debug.print("phdrs_vaddr_order = {any}\n", .{phdrs_vaddr_order});
        std.debug.print("top_vaddr_segs = {any}\n", .{top_vaddr_segs});

        return Self{
            .header = header,
            .phdrs = phdrs,
            .phdrs_offset_order = phdrs_offset_order,
            .phdrs_vaddr_order = phdrs_vaddr_order,
            .top_off_segs = top_off_segs,
            .top_vaddr_segs = top_vaddr_segs,
            .adjustments = try gpa.alloc(usize, containing_count),
            .shdrs = shdrs,
            .shdrs_offset_order = shdrs_offset_order,
            .parse_source = parse_source,
        };
    }

    pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
        gpa.free(self.phdrs_offset_order);
        gpa.free(self.phdrs_vaddr_order);
        gpa.free(self.top_off_segs);
        gpa.free(self.top_vaddr_segs);
        gpa.free(self.adjustments);
        self.phdrs.deinit(gpa);
        gpa.free(self.shdrs_offset_order);
        self.shdrs.deinit(gpa);
    }

    // Get an identifier for the location within the file where additional data could be inserted.
    // TODO: consider if this function should also look at existing gaps to help find the cave which requires the minimal shift.
    pub fn get_cave_option(self: *const Self, wanted_size: u64, p_type: PType, p_flags: PFlags) Error!?SegEdge {
        // NOTE: only dealing with PT_LOAD for now because the other segments frequently overlap with it which is annoyingg.
        std.debug.assert(p_type == PType.PT_LOAD);
        const p_types = self.phdrs.items(Phdr64Fields.p_type);
        const p_flagss = self.phdrs.items(Phdr64Fields.p_flags);
        const p_vaddrs = self.phdrs.items(Phdr64Fields.p_vaddr);
        const p_memszs = self.phdrs.items(Phdr64Fields.p_memsz);
        var i = self.top_off_segs.len;
        while (i > 0) {
            i -= 1;
            const off_idx = self.top_off_segs[i];
            const seg_idx = self.phdrs_offset_order[off_idx];
            if ((@as(PType, @enumFromInt(p_types[seg_idx])) != p_type) or
                (p_flagss[seg_idx] != @as(std.elf.Word, @bitCast(p_flags)))) continue;
            // NOTE: this assumes you dont have an upper bound on possible memory address.
            if ((seg_idx == (p_vaddrs.len - 1)) or
                ((p_vaddrs[seg_idx] + p_memszs[seg_idx] + wanted_size) < p_vaddrs[seg_idx + 1])) return SegEdge{
                .top_idx = i,
                .is_end = true,
            };
            const prev_seg_mem_bound = (if (seg_idx == 0) 0 else (p_vaddrs[seg_idx - 1] + p_memszs[seg_idx - 1]));
            if (p_vaddrs[seg_idx] > (wanted_size + prev_seg_mem_bound)) return SegEdge{
                .top_idx = i,
                .is_end = false,
            };
        }
        return null;
    }

    // TODO: the shoff is not getting updated when I move stuff around, should probably update it.
    fn set_shdr_field(self: *Self, index: usize, val: u64, comptime field_name: []const u8) Error!void {
        std.debug.print("self.header.shoff = {X}\n", .{self.header.shoff});
        try self.parse_source.seekTo(self.header.shoff + self.header.shentsize * index);
        if (self.header.is_64) {
            const T = std.meta.fieldInfo(std.elf.Elf64_Shdr, @field(Shdr64Fields, field_name)).type;
            var temp_buf: [@sizeOf(T)]u8 = undefined;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try self.parse_source.seekBy(@offsetOf(std.elf.Elf64_Shdr, field_name));
            // TODO: should be checking this.
            std.debug.assert(try self.parse_source.read(&temp_buf) == @sizeOf(T));
            try self.parse_source.seekTo(self.header.shoff + self.header.shentsize * index);
            try self.parse_source.seekBy(@offsetOf(std.elf.Elf64_Shdr, field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.print("writing shdr {X} at {X}\n", .{ temp2, try self.parse_source.getPos() });
            std.debug.assert(try self.parse_source.write(&temp2) == @sizeOf(T));
        } else {
            const T = std.meta.fieldInfo(std.elf.Elf32_Shdr, @field(Shdr32Fields, field_name)).type;
            var temp_buf: [@sizeOf(T)]u8 = undefined;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try self.parse_source.seekBy(@offsetOf(std.elf.Elf32_Shdr, field_name));
            // TODO: should be checking this.
            std.debug.assert(try self.parse_source.read(&temp_buf) == @sizeOf(T));
            try self.parse_source.seekTo(self.header.shoff + self.header.shentsize * index);
            try self.parse_source.seekBy(@offsetOf(std.elf.Elf32_Shdr, field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.print("writing shdr {X} at {X}\n", .{ temp2, try self.parse_source.getPos() });
            std.debug.assert(try self.parse_source.write(&temp2) == @sizeOf(T));
        }
        self.shdrs.items(@field(Shdr64Fields, field_name))[index] = @intCast(val);
    }

    // NOTE: field changes must NOT change the memory order or offset order!
    // TODO: consider what to do when setting the segment which holds the phdrtable itself.
    fn set_phdr_field(self: *Self, index: usize, val: u64, comptime field_name: []const u8) Error!void {
        try self.parse_source.seekTo(self.header.phoff + self.header.phentsize * index);
        if (self.header.is_64) {
            const T = std.meta.fieldInfo(std.elf.Elf64_Phdr, @field(Phdr64Fields, field_name)).type;
            var temp_buf: [@sizeOf(T)]u8 = undefined;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try self.parse_source.seekBy(@offsetOf(std.elf.Elf64_Phdr, field_name));
            // TODO: should be checking this.
            std.debug.assert(try self.parse_source.read(&temp_buf) == @sizeOf(T));
            try self.parse_source.seekTo(self.header.phoff + self.header.phentsize * index);
            try self.parse_source.seekBy(@offsetOf(std.elf.Elf64_Phdr, field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.print("writing phdr {X} at {X}\n", .{ temp2, try self.parse_source.getPos() });
            std.debug.assert(try self.parse_source.write(&temp2) == @sizeOf(T));
        } else {
            const T = std.meta.fieldInfo(std.elf.Elf32_Phdr, @field(Phdr32Fields, field_name)).type;
            var temp_buf: [@sizeOf(T)]u8 = undefined;
            var temp: T = @intCast(val);
            temp = if (self.header.endian != native_endian) @as(T, @byteSwap(temp)) else temp;
            try self.parse_source.seekBy(@offsetOf(std.elf.Elf32_Phdr, field_name));
            // TODO: should be checking this.
            std.debug.assert(try self.parse_source.read(&temp_buf) == @sizeOf(T));
            try self.parse_source.seekTo(self.header.phoff + self.header.phentsize * index);
            try self.parse_source.seekBy(@offsetOf(std.elf.Elf32_Phdr, field_name));
            const temp2 = std.mem.toBytes(temp);
            std.debug.print("writing phdr {X} at {X}\n", .{ temp2, try self.parse_source.getPos() });
            std.debug.assert(try self.parse_source.write(&temp2) == @sizeOf(T));
        }
        self.phdrs.items(@field(Phdr64Fields, field_name))[index] = @intCast(val);
    }

    fn calc_new_offset(self: *const Self, top_idx: usize, size: u64) u64 {
        const aligns = self.phdrs.items(Phdr64Fields.p_align);
        const offsets = self.phdrs.items(Phdr64Fields.p_offset);
        const fileszs = self.phdrs.items(Phdr64Fields.p_filesz);
        const index = self.phdrs_offset_order[self.top_off_segs[top_idx]];

        // TODO: add a check first for the case of an ending edge in which there already exists a large enough gap.
        // and for the case of a start edge whith enough space from the previous segment offset.
        const align_offset = (offsets[index] + (aligns[index] - (size % aligns[index]))) % aligns[index];
        const temp = self.phdrs_offset_order[self.top_off_segs[top_idx - 1]];
        const prev_off_end = offsets[temp] + fileszs[temp];
        std.debug.assert(prev_off_end <= offsets[index]);
        const new_offset = if (offsets[index] > (size + prev_off_end))
            (offsets[index] - size)
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
        const aligns = self.phdrs.items(Phdr64Fields.p_align);
        const offsets = self.phdrs.items(Phdr64Fields.p_offset);
        const vaddrs = self.phdrs.items(Phdr64Fields.p_vaddr);
        const paddrs = self.phdrs.items(Phdr64Fields.p_paddr);
        const fileszs = self.phdrs.items(Phdr64Fields.p_filesz);
        const memszs = self.phdrs.items(Phdr64Fields.p_memsz);
        const idx = self.phdrs_offset_order[self.top_off_segs[edge.top_idx]];

        const new_offset: u64 = if (edge.is_end) offsets[idx] else self.calc_new_offset(edge.top_idx, size);
        const first_adjust = if (edge.is_end) size else if (new_offset < offsets[idx]) size - (offsets[idx] - new_offset) else size + (new_offset - offsets[idx]);
        var needed_size = first_adjust;

        var top_idx = edge.top_idx + 1;
        while (top_idx < self.top_off_segs.len) : (top_idx += 1) {
            const offset_seg_index = self.top_off_segs[top_idx];
            const seg_index = self.phdrs_offset_order[offset_seg_index];
            const prev_offset_seg_index = self.top_off_segs[top_idx - 1];
            const prev_seg_index = self.phdrs_offset_order[prev_offset_seg_index];
            const existing_gap = offsets[seg_index] - (offsets[prev_seg_index] + fileszs[prev_seg_index]);
            if (needed_size < existing_gap) break;
            needed_size -= existing_gap;
            // TODO: might be the case that I should be looking at the maximum alignment of all contained segments here.
            if ((aligns[seg_index] != 0) and ((needed_size % aligns[seg_index]) != 0)) needed_size += aligns[seg_index] - (needed_size % aligns[seg_index]);
            self.adjustments[top_idx - (edge.top_idx + 1)] = needed_size;
        }
        var i = top_idx - (edge.top_idx + 1);
        while (i > 0) {
            i -= 1;
            const top_index = i + edge.top_idx + 1;
            const top_off_idx = self.top_off_segs[top_index];
            const top_seg_idx = self.phdrs_offset_order[top_off_idx];
            std.debug.print("shfting forward from {X} to {X} by {X}\n", .{ offsets[top_seg_idx], offsets[top_seg_idx] + fileszs[top_seg_idx], self.adjustments[i] });
            try shift_forward(self.parse_source, offsets[top_seg_idx], offsets[top_seg_idx] + fileszs[top_seg_idx], self.adjustments[i]);
            const final_off_idx = if ((top_index + 1) == self.top_off_segs.len) self.phdrs_offset_order.len else self.top_off_segs[top_index + 1];
            for (top_off_idx..final_off_idx) |seg_offset_index| {
                const seg_index = self.phdrs_offset_order[seg_offset_index];
                try self.set_phdr_field(seg_index, offsets[seg_index] + self.adjustments[i], "p_offset");
            }
        }
        const shdr_offsets = self.shdrs.items(Shdr64Fields.sh_offset);
        const shdr_sizes = self.shdrs.items(Shdr64Fields.sh_size);
        const shdr_addrs = self.shdrs.items(Shdr64Fields.sh_addr);
        var sec_off_idx: usize = 0;
        for (edge.top_idx + 1..top_idx) |top_index| {
            const top_off_idx = self.top_off_segs[top_index];
            const top_seg_idx = self.phdrs_offset_order[top_off_idx];
            while ((sec_off_idx < self.shdrs_offset_order.len) and (shdr_offsets[self.shdrs_offset_order[sec_off_idx]] < (offsets[top_seg_idx] - self.adjustments[top_index - (edge.top_idx + 1)]))) : (sec_off_idx += 1) {}
            while ((sec_off_idx < self.shdrs_offset_order.len) and (shdr_offsets[self.shdrs_offset_order[sec_off_idx]] < ((offsets[top_seg_idx] - self.adjustments[top_index - (edge.top_idx + 1)]) + fileszs[top_seg_idx]))) : (sec_off_idx += 1) {
                const sec_idx = self.shdrs_offset_order[sec_off_idx];
                try self.set_shdr_field(sec_idx, shdr_offsets[sec_idx] + self.adjustments[top_index - (edge.top_idx + 1)], "sh_offset");
            }
        }

        if (!edge.is_end) {
            const top_off_idx = self.top_off_segs[edge.top_idx];
            const top_seg_idx = self.phdrs_offset_order[top_off_idx];
            sec_off_idx = 0;
            while ((sec_off_idx < self.shdrs_offset_order.len) and (shdr_offsets[self.shdrs_offset_order[sec_off_idx]] < offsets[top_seg_idx])) : (sec_off_idx += 1) {}
            while ((sec_off_idx < self.shdrs_offset_order.len) and (shdr_offsets[self.shdrs_offset_order[sec_off_idx]] < (offsets[top_seg_idx] + fileszs[top_seg_idx]))) : (sec_off_idx += 1) {
                const sec_idx = self.shdrs_offset_order[sec_off_idx];
                if (shdr_offsets[sec_idx] == offsets[top_seg_idx]) {
                    try self.set_shdr_field(sec_idx, shdr_sizes[sec_idx] + size, "sh_size");
                    try self.set_shdr_field(sec_idx, shdr_addrs[sec_idx] - size, "sh_addr");
                    try self.set_shdr_field(sec_idx, new_offset, "sh_offset");
                } else {
                    try self.set_shdr_field(sec_idx, shdr_offsets[sec_idx] + first_adjust, "sh_offset");
                }
            }

            std.debug.print("shfting forward from {X} to {X} by {X}\n", .{ offsets[idx], offsets[idx] + fileszs[idx], new_offset + size - offsets[idx] });
            try shift_forward(self.parse_source, offsets[idx], offsets[idx] + fileszs[idx], new_offset + size - offsets[idx]);
            try self.set_phdr_field(idx, vaddrs[idx] - size, "p_vaddr");
            // NOTE: not really sure about the following line.
            try self.set_phdr_field(idx, paddrs[idx] - size, "p_paddr");
            try self.set_phdr_field(idx, new_offset, "p_offset");
        } else {
            const top_off_idx = self.top_off_segs[edge.top_idx];
            const top_seg_idx = self.phdrs_offset_order[top_off_idx];
            sec_off_idx = 0;
            while ((sec_off_idx < self.shdrs_offset_order.len) and (shdr_offsets[self.shdrs_offset_order[sec_off_idx]] < offsets[top_seg_idx])) : (sec_off_idx += 1) {}
            while ((sec_off_idx < self.shdrs_offset_order.len) and (shdr_offsets[self.shdrs_offset_order[sec_off_idx]] < (offsets[top_seg_idx] + fileszs[top_seg_idx]))) : (sec_off_idx += 1) {
                const sec_idx = self.shdrs_offset_order[sec_off_idx];
                if ((shdr_offsets[sec_idx] + shdr_sizes[sec_idx]) == (offsets[top_seg_idx] + fileszs[top_seg_idx])) {
                    try self.set_shdr_field(sec_idx, shdr_sizes[sec_idx] + size, "sh_size");
                }
            }
        }
        try self.set_phdr_field(idx, fileszs[idx] + size, "p_filesz");
        try self.set_phdr_field(idx, memszs[idx] + size, "p_memsz");

        // TODO: adjust sections as well (and maybe debug info?)
    }

    const CompareContext = struct {
        self: *const Self,
        lhs: u64,
    };

    fn addr_compareFn(context: CompareContext, rhs: usize) std.math.Order {
        return std.math.order(context.lhs, context.self.phdrs.items(Phdr64Fields.p_vaddr)[context.self.phdrs_vaddr_order[context.self.top_vaddr_segs[rhs]]]);
    }

    pub fn addr_to_off(self: *const Self, addr: u64) Error!u64 {
        const offsets = self.phdrs.items(Phdr64Fields.p_offset);
        const vaddrs = self.phdrs.items(Phdr64Fields.p_vaddr);
        const fileszs = self.phdrs.items(Phdr64Fields.p_filesz);
        const memszs = self.phdrs.items(Phdr64Fields.p_memsz);
        const containnig_idx = self.addr_to_idx(addr);
        std.debug.print("containnig idx = {}\n", .{containnig_idx});
        if (!(addr < (vaddrs[containnig_idx] + memszs[containnig_idx]))) return Error.AddrNotMapped;
        const potenital_off = offsets[containnig_idx] + addr - vaddrs[containnig_idx];
        if (!(potenital_off < (offsets[containnig_idx] + fileszs[containnig_idx]))) return Error.NoMatchingOffset;
        return potenital_off;
    }

    pub fn addr_to_idx(self: *const Self, addr: u64) usize {
        return self.phdrs_vaddr_order[self.top_vaddr_segs[std.sort.lowerBound(usize, self.top_vaddr_segs, CompareContext{ .self = self, .lhs = addr }, addr_compareFn)]];
    }

    fn off_compareFn(context: CompareContext, rhs: usize) bool {
        return std.math.order(context.lhs, context.self.phdrs.items(Phdr64Fields.p_offset)[context.self.phdrs_offset_order[context.self.top_off_segs[rhs]]]);
    }

    pub fn off_to_addr(self: *const Self, off: u64) Error!u64 {
        const offsets = self.phdrs.items(Phdr64Fields.p_offset);
        const vaddrs = self.phdrs.items(Phdr64Fields.p_vaddr);
        const fileszs = self.phdrs.items(Phdr64Fields.p_filesz);
        const memszs = self.phdrs.items(Phdr64Fields.p_memsz);
        const containnig_idx = self.off_to_idx(off);
        if (!(off < (offsets[containnig_idx] + fileszs[containnig_idx]))) return Error.OffsetNotLoaded;
        // NOTE: cant think of a case where the memsz will be smaller then the filesz (of a top level segment?).
        std.debug.assert(memszs[containnig_idx] >= fileszs[containnig_idx]);
        return vaddrs[containnig_idx] + off - offsets[containnig_idx];
    }

    pub fn off_to_idx(self: *const Self, off: u64) usize {
        return self.phdrs_offset_order[self.top_off_segs[std.sort.upperBound(usize, self.top_off_segs, CompareContext{ .self = self, .lsh = off }, off_compareFn)]];
    }
};

test "create_cave same output" {
    const no_cave_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{ "zig", "run", "./tests/hello_world.zig" },
    });
    defer std.testing.allocator.free(no_cave_result.stdout);
    defer std.testing.allocator.free(no_cave_result.stderr);
    const res = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{ "zig", "build-exe", "./tests/hello_world.zig" },
    });
    defer std.testing.allocator.free(res.stdout);
    defer std.testing.allocator.free(res.stderr);
    {
        var f = try std.fs.cwd().openFile("./hello_world", .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };

        const wanted_size = 0x1000;
        var elf_modder: ElfModder = try ElfModder.init(std.testing.allocator, &stream);
        defer elf_modder.deinit(std.testing.allocator);
        const option = (try elf_modder.get_cave_option(wanted_size, PType.PT_LOAD, PFlags{ .PF_X = true, .PF_R = true })).?;
        try elf_modder.create_cave(wanted_size, option);
    }
    const cave_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{"./hello_world"},
    });
    defer std.testing.allocator.free(cave_result.stdout);
    defer std.testing.allocator.free(cave_result.stderr);
    try std.testing.expect(cave_result.term.Exited == no_cave_result.term.Exited);
    try std.testing.expectEqualStrings(cave_result.stdout, no_cave_result.stdout);
    try std.testing.expectEqualStrings(cave_result.stderr, no_cave_result.stderr);
}
