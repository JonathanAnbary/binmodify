const std = @import("std");
const capstone = @cImport(@cInclude("capstone/capstone.h"));
const ctl_asm = @import("ctl_asm.zig");
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

const Error = error{
    EdgeNotFound,
};

fn shift_forward(stream: *std.io.StreamSource, start: u64, end: u64, amt: u64) !void {
    var buff: [1024]u8 = undefined;
    const shift_start: u64 = blk: {
        if (end < (start + amt)) {
            const temp = try stream.getEndPos();
            if ((start + amt) > temp) try stream.writer().writeByteNTimes(0, start + amt - temp);
            break :blk start;
        } else break :blk end - amt;
    };
    var pos = shift_start;
    while ((pos + buff.len) < end) : (pos += buff.len) {
        try stream.seekTo(pos);
        _ = try stream.read(&buff);
        try stream.seekTo(pos + amt);
        _ = try stream.write(&buff);
    }
    try stream.seekTo(pos);
    _ = try stream.read(buff[0 .. end - pos]);
    try stream.seekTo(pos + amt);
    _ = try stream.write(buff[0 .. end - pos]);
    pos = shift_start;
    while (pos > (start + buff.len)) : (pos -= buff.len) {
        try stream.seekTo(pos - buff.len);
        _ = try stream.read(&buff);
        try stream.seekTo(pos - buff.len + amt);
        _ = try stream.write(&buff);
    }
    try stream.seekTo(start);
    _ = try stream.read(buff[0 .. pos - start]);
    try stream.seekTo(start + amt);
    _ = try stream.write(buff[0 .. pos - start]);
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
    index: u16,
    is_end: bool,
};

pub const ElfModder: type = struct {
    header: std.elf.Header,
    parse_source: *std.io.StreamSource,

    const Self = @This();

    pub fn init(parse_source: *std.io.StreamSource) !Self {
        return Self{
            .parse_source = parse_source,
            .header = try std.elf.Header.read(parse_source),
        };
    }

    // Get an identifier for the location within the file where additional data could be inserted.
    // only considers places which do not require generating an extra segment.
    pub fn get_cave_option(self: Self, wanted_size: u64, p_type: PType, p_flags: PFlags) !?SegEdge {
        var prog_headers = self.header.program_header_iterator(self.parse_source);
        var prev_mem_end: u64 = 0;
        var maybe_curr_prog_header = try prog_headers.next();
        // TODO: assuming that headers are sorted for now.
        // even if these are sorted this doesnt really give the best result...
        // ideally I would sort the pheaders by both file offset and memory offset.
        // file offset will be used for the order of iteration (we want the largest file offset possible for the minimal adjustment).
        // and memory offset will be used to check adjacent segments.
        while (maybe_curr_prog_header) |curr_prog_header| {
            const maybe_next_prog_header = try prog_headers.next();
            defer {
                prev_mem_end = curr_prog_header.p_vaddr + curr_prog_header.p_memsz;
                maybe_curr_prog_header = maybe_next_prog_header;
            }
            std.debug.print("{X}\n", .{curr_prog_header.p_type});
            if ((@as(PType, @enumFromInt(curr_prog_header.p_type)) != p_type) or
                (curr_prog_header.p_flags != @as(@TypeOf(curr_prog_header.p_flags), @bitCast(p_flags)))) continue;
            if ((curr_prog_header.p_vaddr - wanted_size) > prev_mem_end) return SegEdge{
                .index = @intCast(prog_headers.index - 2),
                .is_end = false,
            };
            if (maybe_next_prog_header) |next_prog_header| {
                if ((curr_prog_header.p_vaddr + curr_prog_header.p_memsz + wanted_size) >= next_prog_header.p_vaddr) continue;
            } else return SegEdge{
                .index = @intCast(prog_headers.index - 2),
                .is_end = true,
            };
        }
        return null;
    }

    // NOTE: Doing this the really dumb way for now.
    pub fn create_cave(self: Self, size: u64, edge: SegEdge) !void {
        var prog_headers = self.header.program_header_iterator(self.parse_source);
        var needed_adjust = size;
        prog_headers.index = edge.index + 1;
        for (edge.index..self.header.phnum) |x| {
            const i = self.header.phnum - x;
            needed_adjust = size;
            while (try prog_headers.next()) |*prog_header| {
                if ((prog_header.p_align != 0) and ((needed_adjust % prog_header.p_align) != 0)) needed_adjust += prog_header.p_align - (needed_adjust % prog_header.p_align);
                if (prog_headers.index == i) {
                    try shift_forward(self.parse_source, prog_header.p_offset, prog_header.p_offset + prog_header.p_filesz, needed_adjust);
                    try self.parse_source.seekTo(self.header.phoff + self.header.phentsize * prog_headers.index);
                    if (self.header.is_64) {
                        var new_off: std.elf.Elf64_Off = prog_header.p_offset + needed_adjust;
                        new_off = if (self.header.endian != native_endian) @as(std.elf.Elf64_Off, @byteSwap(new_off)) else new_off;
                        try self.parse_source.seekTo(@offsetOf(std.elf.Elf64_Phdr, "p_offset"));
                        // TODO: should be checking this.
                        _ = try self.parse_source.write(&std.mem.toBytes(new_off));
                    } else {
                        var new_off: std.elf.Elf32_Off = @intCast(prog_header.p_offset + needed_adjust);
                        new_off = if (self.header.endian != native_endian) @as(std.elf.Elf32_Off, @byteSwap(new_off)) else new_off;
                        try self.parse_source.seekTo(@offsetOf(std.elf.Elf32_Phdr, "p_offset"));
                        _ = try self.parse_source.write(&std.mem.toBytes(new_off));
                    }
                    break;
                }
            }
        }
        // TODO: adjust sections as well (and maybe debug info?)
    }
};
//     fn get_patch_buf(comptime ei_class: EI_CLASS, elf: *libelf.Elf, wanted_size: ElfWord(ei_class)) ?BlockInfo {
//         var phdr_num: usize = undefined;
//         if (libelf.elf_getphdrnum(elf, &phdr_num) == -1) {
//             unreachable;
//         }
//         const phdr_table: []ElfPhdr(ei_class) = elf_getphdr(ei_class, elf).?[0..phdr_num];
//         const code_cave_maybe: ?SegEdge = find_code_cave(ei_class, phdr_table, wanted_size);
//         var patch_buf_off: ElfOff(ei_class) = undefined;
//         var patch_buf_addr: ElfAddr(ei_class) = undefined;
//         var patch_buf: *[]u8 = undefined;
//         var scn: *libelf.Elf_Scn = undefined;
//         if (code_cave_maybe) |code_cave| {
//             const adjust_size = blk: {
//                 if (code_cave.is_end) {
//                     patch_buf_off = phdr_table[code_cave.index].p_offset + phdr_table[code_cave.index].p_filesz;
//                     patch_buf_addr = phdr_table[code_cave.index].p_vaddr + phdr_table[code_cave.index].p_memsz;
//                     scn = find_scn_by_end(ei_class, elf, patch_buf_off).?;
//                     patch_buf = extend_scn_forword(ei_class, scn, wanted_size);
//                     break :blk wanted_size;
//                 } else {
//                     phdr_table[code_cave.index].p_vaddr -= wanted_size;
//                     phdr_table[code_cave.index].p_paddr -= wanted_size;
//                     const align_size: ElfWord(ei_class) = @intCast(phdr_table[code_cave.index].p_align - (wanted_size % phdr_table[code_cave.index].p_align));
//                     phdr_table[code_cave.index].p_offset += align_size;
//                     patch_buf_off = phdr_table[code_cave.index].p_offset;
//                     patch_buf_addr = phdr_table[code_cave.index].p_vaddr;
//                     scn = find_scn_by_start(ei_class, elf, patch_buf_off).?;
//                     patch_buf = extend_scn_backword(ei_class, scn, wanted_size, align_size);
//                     break :blk wanted_size + align_size;
//                 }
//             };
//             phdr_table[code_cave.index].p_filesz += wanted_size;
//             phdr_table[code_cave.index].p_memsz += wanted_size;
//             // adjusting the file offsets of the segments and secttions, other things might also need adjustment but I truly dont know.
//             std.debug.print("flagging = {}\n", .{libelf.elf_flagelf(elf, libelf.ELF_C_SET, libelf.ELF_F_LAYOUT)});
//             adjust_elf_file(ei_class, elf, phdr_table, patch_buf_off, adjust_size);
//             // adjust_segs_after(ei_class, phdr_table, patch_buf_off, wanted_size);
//             // std.debug.print("flagging = {}\n ", .{libelf.elf_flagphdr(elf, libelf.ELF_C_SET, libelf.ELF_F_DIRTY)});
//             // the minus one is because we need to adjust the section that starts right at the start of the segment (unlike with the segment where we just adjusted it).
//             // const cume_adjust = adjust_scns_after(ei_class, elf, patch_buf_off, wanted_size);
//             // adjust_ehdr(ei_class, elf, patch_buf_off, cume_adjust);
//         } else {
//             const new_phdr_table = new_seg_code_buf(ei_class, elf, phdr_table, wanted_size);
//             patch_buf_off = new_phdr_table[new_phdr_table.len - 1].p_offset;
//             patch_buf_addr = new_phdr_table[new_phdr_table.len - 1].p_vaddr;
//         }
//
//         std.debug.print("patch_buf_off = {x}\npatch_buf_addr = {x}\n", .{ patch_buf_off, patch_buf_addr });
//
//         std.debug.print("new section loc = {x}\n", .{patch_buf_off});
//         std.debug.print("new section size = {}\n", .{wanted_size});
//
//         return BlockInfo{ .block = patch_buf, .addr = patch_buf_addr };
//     }
// };
//
// fn get_off_phdr(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOff(ei_class)) ?*ElfPhdr(ei_class) {
//     const temp: [*]ElfPhdr(ei_class) = elf_getphdr(ei_class, elf).?;
//     var phdr_num: usize = undefined;
//     if (libelf.elf_getphdrnum(elf, &phdr_num) == -1) {
//         unreachable;
//     }
//     const phdr_table: []ElfPhdr(ei_class) = temp[0..phdr_num];
//     for (phdr_table) |*phdr| {
//         if (off < (phdr.p_offset + phdr.p_filesz)) {
//             return phdr;
//         }
//     }
//     return null;
// }
//
// fn get_off_scn(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOff(ei_class)) ?*libelf.Elf_Scn {
//     var curr_scn: ?*libelf.Elf_Scn = null;
//     while (libelf.elf_nextscn(elf, curr_scn)) |scn| : (curr_scn = scn) {
//         const parsed_shdr = elf_getshdr(ei_class, scn) orelse {
//             unreachable;
//         };
//         if ((off > parsed_shdr.sh_offset) and (off < (parsed_shdr.sh_offset + parsed_shdr.sh_size))) {
//             return scn;
//         }
//     }
//     return null;
// }
//
// fn get_scn_off_data(comptime ei_class: EI_CLASS, scn: *libelf.Elf_Scn, shdr: *ElfShdr(ei_class), off: ElfOff(ei_class)) ?*libelf.Elf_Data {
//     var curr_data: ?*libelf.Elf_Data = null;
//     while (@as(?*libelf.Elf_Data, @ptrCast(libelf.elf_getdata(scn, curr_data)))) |data| : (curr_data = data) {
//         if ((off > data.d_off + @as(isize, @intCast(shdr.sh_offset))) and
//             (off < (data.d_off + @as(isize, @intCast(shdr.sh_offset)) + @as(isize, @intCast(data.d_size)))))
//         {
//             return data;
//         }
//     }
//     return null;
// }
//
//
// fn get_addr(seg_idx: u32, is_end: bool, ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class)) u64 {
//     if (is_end) {
//         return phdr_table[seg_idx].p_offset + phdr_table[seg_idx].p_filesz;
//     }
//     return phdr_table[seg_idx].p_offset;
// }
//
// fn get_off(seg_idx: u32, is_end: bool, ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class)) u64 {
//     if (is_end) {
//         return phdr_table[seg_idx].p_offset + phdr_table[seg_idx].p_filesz;
//     }
//     return phdr_table[seg_idx].p_offset;
// }
//
// fn get_gap_size(seg_prox: SegEdge, ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class)) u64 {
//     const start: u64 = blk: {
//         if (seg_prox.is_end) {
//             break :blk get_off(seg_prox, ei_class, phdr_table);
//         } else if (seg_prox.index != 0) {
//             break :blk get_off(SegEdge{ .index = seg_prox.index - 1, .is_end = true }, ei_class, phdr_table);
//         } else {
//             break :blk 0;
//         }
//     };
//     const end: u64 = blk: {
//         if (!seg_prox.is_end) {
//             break :blk get_off(seg_prox, ei_class, phdr_table);
//         } else if (seg_prox.index != (phdr_table.len - 1)) {
//             break :blk get_off(SegEdge{ .index = seg_prox.index + 1, .is_end = false }, ei_class, phdr_table);
//         } else {
//             break :blk std.math.maxInt(u64);
//         }
//     };
//     return end - start;
// }
//
// fn gen_is_code_seg(comptime ei_class: EI_CLASS) fn (phdr: ElfPhdr(ei_class)) bool {
//     return struct {
//         pub fn foo(phdr: ElfPhdr(ei_class)) bool {
//             return ((phdr.p_type == libelf.PT_LOAD) and (phdr.p_flags & (libelf.PF_R | libelf.PF_X) == (libelf.PF_R | libelf.PF_X)));
//         }
//     }.foo;
// }
//
// fn gen_is_load(comptime ei_class: EI_CLASS) fn (phdr: ElfPhdr(ei_class)) bool {
//     return struct {
//         pub fn foo(phdr: ElfPhdr(ei_class)) bool {
//             return phdr.p_type == libelf.PT_LOAD;
//         }
//     }.foo;
// }
//
// fn find(start: u16, end: u16, jump: i32, arr: anytype, comptime cond: fn (item: @typeInfo(@TypeOf(arr)).Pointer.child) bool) ?u16 {
//     switch (@typeInfo(@TypeOf(arr))) {
//         .Pointer => {},
//         else => @compileError("can only search through arrays.\n"),
//     }
//     std.debug.assert(jump != 0);
//     if ((start < end) != (jump > 0)) {
//         return null;
//     }
//     var i: u16 = start;
//     while (i != end) : (i = @as(u16, @intCast(@as(i32, @intCast(i)) + jump))) {
//         if (cond(arr[i])) {
//             return i;
//         }
//     }
//     return null;
// }
//
// const BlockInfo: type = struct {
//     block: *[]u8,
//     addr: u64,
// };
//
// fn gen_less_then_shdr(ei_class: EI_CLASS) fn (elf: *libelf.Elf, u8, u8) bool {
//     return struct {
//         pub fn foo(elf: *libelf.Elf, lhs: u8, rhs: u8) bool {
//             const lhs_scn = libelf.elf_getscn(elf, lhs).?;
//             const lhs_shdr = elf_getshdr(ei_class, lhs_scn).?;
//             const rhs_scn = libelf.elf_getscn(elf, rhs).?;
//             const rhs_shdr = elf_getshdr(ei_class, rhs_scn).?;
//             return (lhs_shdr.sh_offset < rhs_shdr.sh_offset) or ((lhs_shdr.sh_offset == rhs_shdr.sh_offset) and (lhs < rhs));
//         }
//     }.foo;
// }
//
// fn gen_less_then_phdr(comptime ei_class: EI_CLASS) fn (phdr_table: []ElfPhdr(ei_class), u8, u8) bool {
//     return struct {
//         pub fn foo(phdr_table: []ElfPhdr(ei_class), lhs: u8, rhs: u8) bool {
//             return (phdr_table[lhs].p_offset < phdr_table[rhs].p_offset) or ((phdr_table[lhs].p_offset == phdr_table[rhs].p_offset) and (lhs < rhs));
//         }
//     }.foo;
// }
//
// fn adjust_elf_file(comptime ei_class: EI_CLASS, elf: *libelf.Elf, phdr_table: []ElfPhdr(ei_class), after: ElfOff(ei_class), amount: ElfWord(ei_class)) void {
//     var max_sortable_phdr_table: [std.math.maxInt(u8)]u8 = comptime blk: {
//         var temp: [std.math.maxInt(u8)]u8 = undefined;
//         for (0..std.math.maxInt(u8)) |i| {
//             temp[i] = i;
//         }
//         break :blk temp;
//     };
//     var max_sortable_shdr_table: [std.math.maxInt(u8)]u8 = comptime blk: {
//         var temp: [std.math.maxInt(u8)]u8 = undefined;
//         for (0..std.math.maxInt(u8)) |i| {
//             temp[i] = i;
//         }
//         break :blk temp;
//     };
//     const sortable_phdr_table = max_sortable_phdr_table[0..phdr_table.len];
//     var shdrnum: usize = undefined;
//     if (libelf.elf_getshdrnum(elf, &shdrnum) == -1) {
//         unreachable;
//     }
//     const sortable_shdr_table = max_sortable_shdr_table[0..shdrnum];
//     std.sort.heap(u8, sortable_phdr_table, phdr_table, gen_less_then_phdr(ei_class));
//     std.sort.heap(u8, sortable_shdr_table, elf, gen_less_then_shdr(ei_class));
//     var cume_adjust: ElfWord(ei_class) = 0;
//     var min_adjust: ElfWord(ei_class) = amount;
//     var sorted_shdr_idx: u8 = 0;
//     var sorted_phdr_idx: u8 = 0;
//     std.debug.print("sortable_phdr_table = {any}\n", .{sortable_phdr_table});
//     std.debug.print("sortable_shdr_table = {any}\n", .{sortable_shdr_table});
//     while (sorted_phdr_idx < sortable_phdr_table.len) : (sorted_phdr_idx += 1) {
//         const phdr_idx = sortable_phdr_table[sorted_phdr_idx];
//         if (phdr_table[phdr_idx].p_offset > after) {
//             const diff = (min_adjust % phdr_table[phdr_idx].p_align);
//             if (diff != 0) {
//                 min_adjust += @as(ElfWord(ei_class), @intCast(phdr_table[phdr_idx].p_align - diff));
//             }
//             while (sorted_shdr_idx < sortable_shdr_table.len) {
//                 const scn = libelf.elf_getscn(elf, sortable_shdr_table[sorted_shdr_idx]).?;
//                 const shdr = elf_getshdr(ei_class, scn).?;
//                 // we look at the start of the next segment instead of the end of the current one to account for sections between segments (or after all of the segments).
//                 // there is no need to consider sections which come before the segments since the patch always occures in a segement.
//                 if ((sorted_phdr_idx < sortable_phdr_table.len - 1) and
//                     (shdr.sh_offset > (phdr_table[sortable_phdr_table[sorted_phdr_idx + 1]].p_offset)))
//                 {
//                     break;
//                 }
//                 if (shdr.sh_offset < phdr_table[phdr_idx].p_offset) {
//                     sorted_shdr_idx += 1;
//                     continue;
//                 }
//                 shdr.sh_offset += min_adjust;
//                 sorted_shdr_idx += 1;
//             }
//             phdr_table[phdr_idx].p_offset += min_adjust;
//             cume_adjust += min_adjust;
//         }
//     }
//     // for (sortable_shdr_table[sorted_shdr_idx..]) |shdr_idx| {
//     //     const scn = libelf.elf_getscn(elf, shdr_idx).?;
//     //     const shdr = elf_getshdr(ei_class, scn).?;
//     //     shdr.sh_offset += min_adjust;
//     // }
//     var ehdr: *ElfEhdr(ei_class) = elf_getehdr(ei_class, elf).?;
//     if (ehdr.e_shoff > after) {
//         ehdr.e_shoff += cume_adjust;
//     }
// }
//
// // do I maybe need tto make sure the adjustments I make stay aligned?
// fn adjust_segs_after(comptime ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class), after: ElfOff(ei_class), amount: ElfWord(ei_class)) void {
//     var cume_adjust: ElfWord(ei_class) = 0;
//     var min_adjust: ElfWord(ei_class) = amount;
//     for (phdr_table) |*phdr| {
//         if (phdr.p_offset > after) {
//             min_adjust += @as(ElfWord(ei_class), @intCast(phdr.p_align - (min_adjust % phdr.p_align)));
//             phdr.p_offset += min_adjust;
//             cume_adjust += min_adjust;
//             // phdr.p_offset += amount;
//         }
//     }
// }
//
// // dont know what would happend if there were a section crossing segment boundries.
// fn adjust_scns_after(comptime ei_class: EI_CLASS, elf: *libelf.Elf, after: ElfOff(ei_class), amount: ElfWord(ei_class)) ElfWord(ei_class) {
//     var shdrnum: usize = undefined;
//     if (libelf.elf_getshdrnum(elf, &shdrnum) == -1) {
//         unreachable;
//     }
//     var cume_adjust: ElfWord(ei_class) = 0;
//     var min_adjust: ElfWord(ei_class) = amount;
//     for (0..shdrnum) |i| {
//         const scn: *libelf.Elf_Scn = libelf.elf_getscn(elf, i).?;
//         var shdr: *ElfShdr(ei_class) = elf_getshdr(ei_class, scn).?;
//         if (shdr.sh_offset > after) {
//             min_adjust += @as(ElfWord(ei_class), @intCast(shdr.sh_addralign - (min_adjust % shdr.sh_addralign)));
//             shdr.sh_offset += min_adjust;
//             cume_adjust += min_adjust;
//             // std.debug.print("flagging = {}\n ", .{libelf.elf_flagscn(scn, libelf.ELF_C_SET, libelf.ELF_F_DIRTY)});
//             std.debug.print("flagging = {}\n ", .{libelf.elf_flagshdr(scn, libelf.ELF_C_SET, libelf.ELF_F_DIRTY)});
//         }
//     }
//     return cume_adjust;
// }
//
// fn adjust_ehdr(comptime ei_class: EI_CLASS, elf: *libelf.Elf, after: ElfOff(ei_class), amount: ElfWord(ei_class)) void {
//     var ehdr: *ElfEhdr(ei_class) = elf_getehdr(ei_class, elf).?;
//     if (ehdr.e_shoff > after) {
//         ehdr.e_shoff += amount;
//     }
// }
//
// fn get_last_file_seg(comptime ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class)) ?u16 {
//     var max: u16 = @intCast(find(0, @as(u16, @intCast(phdr_table.len - 1)), 1, phdr_table, gen_is_load(ei_class)) orelse return null);
//     if (max == phdr_table.len - 1) return max;
//     for (max + 1..phdr_table.len) |i| {
//         if (phdr_table[i].p_offset > phdr_table[max].p_offset) {
//             max = @intCast(i);
//         }
//     }
//     return max;
// }
//
// fn get_last_mem_seg(comptime ei_class: EI_CLASS, phdr_table: []ElfPhdr(ei_class)) ?u16 {
//     var max: u16 = @intCast(find(0, @as(u16, @intCast(phdr_table.len - 1)), 1, phdr_table, gen_is_load(ei_class)) orelse return null);
//     if (max == phdr_table.len - 1) return max;
//     for (max + 1..phdr_table.len) |i| {
//         if ((gen_is_load(ei_class)(phdr_table[i])) and (phdr_table[i].p_vaddr > phdr_table[max].p_vaddr)) {
//             max = @intCast(i);
//         }
//     }
//     return max;
// }
//
// fn elf_newphdr(comptime ei_class: EI_CLASS, elf: *libelf.Elf, count: u16) ?[*]ElfPhdr(ei_class) {
//     return switch (ei_class) {
//         inline .ELFCLASS32 => libelf.elf32_newphdr(elf, count),
//         inline .ELFCLASS64 => libelf.elf64_newphdr(elf, count),
//     };
// }
//
// fn off_to_addr(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOff(ei_class)) ?ElfAddr(ei_class) {
//     const phdr = get_off_phdr(ei_class, elf, off) orelse return null;
//     return off - phdr.p_offset + phdr.p_vaddr;
// }
//
// fn get_off_data(comptime ei_class: EI_CLASS, elf: *libelf.Elf, off: ElfOff(ei_class)) ?[]u8 {
//     const scn: *libelf.Elf_Scn = get_off_scn(ei_class, elf, off).?;
//     const shdr = elf_getshdr(ei_class, scn).?;
//     const off_data: *libelf.Elf_Data = get_scn_off_data(ei_class, scn, shdr, off).?;
//     const patch_scn_off: ElfOff(ei_class) = off - shdr.sh_offset;
//     const patch_loc_data: []u8 = @as([*]u8, @ptrCast(off_data.d_buf.?))[patch_scn_off - @as(u64, @intCast(off_data.d_off)) .. off_data.d_size];
//     return patch_loc_data;
// }
//
// // this is kind of grossly inefficient but I cant think of how to make it better.
// fn calc_min_move(csh: capstone.csh, insns: []const u8, wanted_size: u64) u64 {
//     const insn: *capstone.cs_insn = capstone.cs_malloc(csh);
//     defer capstone.cs_free(insn, 1);
//     var curr_code = insns;
//     var curr_size = insns.len;
//     const start: u64 = 0;
//     var end: u64 = start;
//     while ((end - start) < wanted_size) {
//         if (!capstone.cs_disasm_iter(
//             csh,
//             @as([*c][*c]const u8, @ptrCast(&curr_code)),
//             &curr_size,
//             &end,
//             insn,
//         )) {
//             unreachable;
//         }
//     }
//
//     return end - start;
// }
//
// fn insert_jmp(ctlfh: ctl_asm.CtlFlowAssembler, patch_loc: []u8, target: u64, addr: u64) !usize {
//     return (try ctlfh.assemble_ctl_transfer(target, addr, patch_loc)).len;
// }
//
// fn find_code_cave(program_header_iterator: std.elf.ProgramHeaderIterator, wanted_size: u64) ?SegEdge {
//     var prev: u16 = find(0, @intCast(phdr_table.len), 1, phdr_table, gen_is_load(ei_class)).?;
//     var curr: u16 = find(prev + 1, @intCast(phdr_table.len), 1, phdr_table, gen_is_load(ei_class)).?;
//     if (gen_is_code_seg(ei_class)(phdr_table[prev])) {
//         // if (wanted_size < phdr_table[prev].p_vaddr) {
//         //     return SegEdge{ .seg_idx = prev, .is_end = false };
//         // }
//         if ((phdr_table[prev].p_memsz <= phdr_table[prev].p_filesz) and (wanted_size < (phdr_table[curr].p_vaddr - (phdr_table[prev].p_vaddr + phdr_table[prev].p_memsz)))) {
//             return SegEdge{ .index = prev, .is_end = true };
//         }
//     }
//     while (find(curr + 1, @intCast(phdr_table.len), 1, phdr_table, gen_is_load(ei_class))) |next| {
//         if (gen_is_code_seg(ei_class)(phdr_table[curr])) {
//             // if (wanted_size < (phdr_table[curr].p_vaddr - (phdr_table[prev].p_vaddr + phdr_table[prev].p_memsz))) {
//             //     return SegEdge{ .seg_idx = curr, .is_end = false };
//             // }
//             if ((phdr_table[curr].p_memsz <= phdr_table[curr].p_filesz) and (wanted_size < (phdr_table[next].p_vaddr - (phdr_table[curr].p_vaddr + phdr_table[curr].p_memsz)))) {
//                 return SegEdge{ .index = curr, .is_end = true };
//             }
//         }
//         prev = curr;
//         curr = next;
//     }
//     if (gen_is_code_seg(ei_class)(phdr_table[curr])) {
//         // if (wanted_size < (phdr_table[curr].p_vaddr - (phdr_table[prev].p_vaddr + phdr_table[prev].p_memsz))) {
//         //     return SegEdge{ .seg_idx = curr, .is_end = false };
//         // }
//         if (wanted_size < (std.math.maxInt(ElfWord(ei_class)) - phdr_table[curr].p_vaddr)) {
//             return SegEdge{ .index = curr, .is_end = true };
//         }
//     }
//     return null;
// }
//
// fn new_seg_code_buf(comptime ei_class: EI_CLASS, elf: *libelf.Elf, old_phdr_table: []ElfPhdr(ei_class), size: ElfWord(ei_class)) []ElfPhdr(ei_class) {
//     std.debug.print("prev_phdr_table[0] = {}\n", .{old_phdr_table[0]});
//     const last_mem_seg_idx: u16 = get_last_mem_seg(ei_class, old_phdr_table).?;
//     const last_file_seg_idx: u16 = get_last_file_seg(ei_class, old_phdr_table).?;
//     const first_phdr = old_phdr_table[0];
//     const new_phdr_table: []ElfPhdr(ei_class) = elf_newphdr(ei_class, elf, @intCast(old_phdr_table.len + 1)).?[0 .. old_phdr_table.len + 1];
//     // this feels like bullshit (I should either have to save the whole table or not save at all), saving only the first is wierd.
//     std.mem.copyBackwards(ElfPhdr(ei_class), new_phdr_table[1..], old_phdr_table[1..]);
//     new_phdr_table[0] = first_phdr;
//     std.debug.print("phdr_table[0] = {}\n", .{old_phdr_table[0]});
//     const new_mem_seg_idx: u16 = @intCast(old_phdr_table.len);
//
//     std.debug.print("last_mem_seg_idx = {}\nlast_file_seg_idx = {}\n", .{ last_mem_seg_idx, last_file_seg_idx });
//     std.debug.print("last_mem_phdr = {}\nlast_file_phdr = {}\n", .{ new_phdr_table[last_mem_seg_idx], new_phdr_table[last_file_seg_idx] });
//     const vmem_end = new_phdr_table[last_mem_seg_idx].p_vaddr + new_phdr_table[last_mem_seg_idx].p_memsz;
//     const pmem_end = new_phdr_table[last_mem_seg_idx].p_paddr + new_phdr_table[last_mem_seg_idx].p_memsz;
//
//     new_phdr_table[new_mem_seg_idx].p_type = libelf.PT_LOAD;
//     new_phdr_table[new_mem_seg_idx].p_flags = libelf.PF_X | libelf.PF_R;
//     new_phdr_table[new_mem_seg_idx].p_align = 0x1000;
//     new_phdr_table[new_mem_seg_idx].p_offset = new_phdr_table[last_file_seg_idx].p_offset + new_phdr_table[last_file_seg_idx].p_filesz;
//     new_phdr_table[new_mem_seg_idx].p_vaddr = vmem_end + (new_phdr_table[last_mem_seg_idx].p_align - vmem_end % new_phdr_table[last_mem_seg_idx].p_align);
//     new_phdr_table[new_mem_seg_idx].p_paddr = pmem_end + (new_phdr_table[last_mem_seg_idx].p_align - pmem_end % new_phdr_table[last_mem_seg_idx].p_align);
//     new_phdr_table[new_mem_seg_idx].p_filesz = size;
//     new_phdr_table[new_mem_seg_idx].p_memsz = size;
//
//     return new_phdr_table;
// }
//
// fn create_elf_data(comptime ei_class: EI_CLASS, elf: *libelf.Elf, addr: ElfAddr(ei_class), off: ElfOff(ei_class), size: ElfWord(ei_class)) *libelf.Elf_Data {
//     const scn = libelf.elf_newscn(elf).?;
//
//     var shdr: *ElfShdr(ei_class) = elf_getshdr(ei_class, scn).?;
//     shdr.sh_name = 2;
//     shdr.sh_type = libelf.SHT_PROGBITS;
//     shdr.sh_flags = libelf.SHF_ALLOC | libelf.SHF_EXECINSTR;
//     shdr.sh_addr = addr;
//     shdr.sh_offset = off;
//     shdr.sh_size = size;
//     shdr.sh_link = 0;
//     shdr.sh_info = 0;
//     shdr.sh_addralign = 4;
//     shdr.sh_entsize = 0;
//
//     var d: *libelf.Elf_Data = libelf.elf_newdata(scn).?;
//     d.d_align = 8;
//     d.d_off = 0;
//     d.d_buf = null;
//     d.d_type = libelf.ELF_T_BYTE;
//     d.d_size = size;
//     d.d_version = libelf.EV_CURRENT;
//
//     return d;
// }
//
// fn extend_scn_forword(comptime ei_class: EI_CLASS, scn: *libelf.Elf_Scn, extend_size: ElfWord(ei_class)) *[]u8 {
//     const shdr: *ElfShdr(ei_class) = elf_getshdr(ei_class, scn).?;
//     shdr.sh_size += extend_size;
//     const d: *libelf.Elf_Data = libelf.elf_newdata(scn);
//     d.d_type = libelf.ELF_T_BYTE;
//     d.d_size = extend_size;
//     d.d_off = @intCast(shdr.sh_size - extend_size);
//     d.d_align = 8;
//     d.d_version = libelf.EV_CURRENT;
//     return @ptrCast(&d.d_buf);
// }
//
// fn find_scn_by_end(comptime ei_class: EI_CLASS, elf: *libelf.Elf, end: ElfOff(ei_class)) ?*libelf.Elf_Scn {
//     var shdrnum: usize = undefined;
//     if (libelf.elf_getshdrnum(elf, &shdrnum) == -1) {
//         unreachable;
//     }
//     for (0..shdrnum) |i| {
//         const scn: *libelf.Elf_Scn = libelf.elf_getscn(elf, i).?;
//         const shdr: *ElfShdr(ei_class) = elf_getshdr(ei_class, scn).?;
//         if ((shdr.sh_offset + shdr.sh_size) == end) {
//             return scn;
//         }
//     }
//     return null;
// }
//
// // I might need to move around the other data parts of the section.
// fn clear_data_backword(comptime ei_class: EI_CLASS, scn: *libelf.Elf_Scn, extend_size: ElfWord(ei_class)) void {
//     var data_maybe: ?*libelf.Elf_Data = null;
//     while (@as(?*libelf.Elf_Data, @ptrCast(libelf.elf_getdata(scn, data_maybe)))) |data| {
//         data.d_off += extend_size;
//         data_maybe = data;
//     }
//     // return null;
// }
//
// fn extend_scn_backword(comptime ei_class: EI_CLASS, scn: *libelf.Elf_Scn, extend_size: ElfWord(ei_class), align_size: ElfWord(ei_class)) *[]u8 {
//     const shdr: *ElfShdr(ei_class) = elf_getshdr(ei_class, scn).?;
//     shdr.sh_size += extend_size;
//     shdr.sh_addr -= extend_size;
//     shdr.sh_offset += align_size;
//     clear_data_backword(ei_class, scn, extend_size);
//     const d: *libelf.Elf_Data = libelf.elf_newdata(scn).?;
//     d.d_type = libelf.ELF_T_BYTE;
//     d.d_size = extend_size;
//     d.d_off = 0;
//     d.d_align = 8;
//     d.d_version = libelf.EV_CURRENT;
//     return @ptrCast(&d.d_buf);
// }
//
// fn find_scn_by_start(comptime ei_class: EI_CLASS, elf: *libelf.Elf, start: ElfOff(ei_class)) ?*libelf.Elf_Scn {
//     var shdrnum: usize = undefined;
//     if (libelf.elf_getshdrnum(elf, &shdrnum) == -1) {
//         unreachable;
//     }
//     for (0..shdrnum) |i| {
//         const scn: *libelf.Elf_Scn = libelf.elf_getscn(elf, i).?;
//         const shdr: *ElfShdr(ei_class) = elf_getshdr(ei_class, scn).?;
//         if (shdr.sh_offset == start) {
//             return scn;
//         }
//     }
//     return null;
// }
//
// const MAX_JMP_SIZE = 5; // this is based on x86_64, might need to do some actual work to make this cross architecture.
//
// fn min_buf_size(csh: capstone.csh, insn: []const u8, patch_len: u64) u64 {
//     const moved_insn_len = calc_min_move(csh, insn, MAX_JMP_SIZE);
//     return patch_len + moved_insn_len + MAX_JMP_SIZE;
// }
//
// fn insert_patch(
//     csh: capstone.csh,
//     ctlfh: ctl_asm.CtlFlowAssembler,
//     to_patch: BlockInfo,
//     patch_buf: BlockInfo,
//     patch_data: []const u8,
// ) !void {
//     const move_insn_size: u64 = @intCast(calc_min_move(csh, to_patch.block.*, MAX_JMP_SIZE));
//     @memcpy(patch_buf.block.*[0..patch_data.len], patch_data);
//     @memcpy(patch_buf.block.*[patch_data.len .. patch_data.len + move_insn_size], to_patch.block.*[0..move_insn_size]);
//     std.debug.print("inserting escape jmp\n", .{});
//     std.debug.print("escape_jmp_addr = {x}\ntarget_addr = {x}\nmoved_insn_size = {x}\n", .{ to_patch.addr, patch_buf.addr, move_insn_size });
//     _ = try insert_jmp(ctlfh, to_patch.block.*, patch_buf.addr, to_patch.addr);
//     const jmp_back_insn_addr = patch_buf.addr + patch_data.len + move_insn_size;
//     const jmp_back_target_addr = to_patch.addr + move_insn_size;
//
//     std.debug.print("inserting jmp back\n", .{});
//     std.debug.print("jmp_back_addr = {x}\naddr = {x}\nmoved_insn_size = {x}\n", .{ jmp_back_insn_addr, to_patch.addr, move_insn_size });
//     _ = try insert_jmp(ctlfh, patch_buf.block.*[patch_data.len + move_insn_size ..], jmp_back_target_addr, jmp_back_insn_addr);
// }
//
// fn print_elf(comptime ei_class: EI_CLASS, elf: *libelf.Elf) void {
//     // const ehdr: *ElfEhdr(ei_class) = elf_getehdr(ei_class, elf).?;
//     // std.debug.print("ehdr = {}\n", .{ehdr});
//     // const temp: [*]ElfPhdr(ei_class) = elf_getphdr(ei_class, elf).?;
//     // var phdr_num: usize = undefined;
//     // if (libelf.elf_getphdrnum(elf, &phdr_num) == -1) {
//     //     unreachable;
//     // }
//     // const phdr_table: []ElfPhdr(ei_class) = temp[0..phdr_num];
//     // std.debug.print("phdr table = \n{any}\n", .{phdr_table});
//     std.debug.print("shdr table:\nindex name type flags addr      offset  size   link info align entsize offset+size\n", .{});
//     var shdrnum: usize = undefined;
//     if (libelf.elf_getshdrnum(elf, &shdrnum) == -1) {
//         unreachable;
//     }
//     for (0..shdrnum) |i| {
//         const scn: *libelf.Elf_Scn = libelf.elf_getscn(elf, i).?;
//         const shdr: *ElfShdr(ei_class) = elf_getshdr(ei_class, scn).?;
//         std.debug.print("[{d:0>2}]  {: <4} {: <4} {: <5} {x: <9} {x: <7} {x: <6} {: <4} {: <4} {x: <5} {: <7} {x: <7}\n", .{ i, shdr.sh_name, shdr.sh_type, shdr.sh_flags, shdr.sh_addr, shdr.sh_offset, shdr.sh_size, shdr.sh_link, shdr.sh_info, shdr.sh_addralign, shdr.sh_entsize, shdr.sh_offset + shdr.sh_size });
//     }
// }
