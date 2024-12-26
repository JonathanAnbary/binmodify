const std = @import("std");
const native_endian = @import("builtin").target.cpu.arch.endian();

fn off_lessThanFn(sechdrs: []align(1) const std.coff.SectionHeader, lhs: usize, rhs: usize) bool {
    return sechdrs[lhs].pointer_to_raw_data < sechdrs[rhs].pointer_to_raw_data;
}

// TODO: consider if this should have a similar logic, where segments which "contain" other segments come first.
fn vaddr_lessThanFn(sechdrs: []align(1) const std.coff.SectionHeader, lhs: usize, rhs: usize) bool {
    return sechdrs[lhs].virtual_address < sechdrs[rhs].virtual_address;
}

pub const Error = error{};

pub const SecEdge: type = struct {
    sec_idx: usize,
    is_end: bool,
};

pub const CoffModder: type = struct {
    coff: std.coff.Coff,
    sechdrs_off_order: []usize,
    sec_to_off: []usize,
    sechdrs_vaddr_order: []usize,
    sec_to_vaddr: []usize,
    // // TODO: dont really need this, can just calculate it as I go by.
    // not sure if this is actually needed for coff.
    // top_off_segs: []usize,
    // top_vaddr_segs: []usize,
    // adjustments: []usize,
    data: []const u8,

    const Self = @This();

    pub fn init(gpa: std.mem.Allocator, data: []const u8) Error!Self {
        const coff = try std.coff.Coff.init(data, false);
        const sechdrs = coff.getSectionHeaders();
        const sechdrs_vaddr_order = gpa.alloc(usize, sechdrs.len);
        const sechdrs_off_order = gpa.alloc(usize, sechdrs.len);
        for (0..sechdrs.len) |i| {
            sechdrs_vaddr_order[i] = i;
            sechdrs_off_order[i] = i;
        }
        std.sort.pdq(usize, sechdrs_vaddr_order, sechdrs, off_lessThanFn);
        std.sort.pdq(usize, sechdrs_off_order, sechdrs, vaddr_lessThanFn);
        const sec_to_off = gpa.alloc(usize, sechdrs.len);
        const sec_to_vaddr = gpa.alloc(usize, sechdrs.len);
        for (sechdrs_off_order, sechdrs_vaddr_order, 0..) |off_idx, vaddr_idx, idx| {
            sec_to_off[off_idx] = idx;
            sec_to_vaddr[vaddr_idx] = idx;
        }
        return Self{
            .coff = coff,
            .sechdrs_vaddr_order = sechdrs_vaddr_order,
            .sec_to_off = sec_to_off,
            .sechdrs_off_order = sechdrs_off_order,
            .sec_to_vaddr = sec_to_vaddr,
            .data = data,
        };
    }

    pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
        gpa.free(self.sechdrs_off_order);
        gpa.free(self.sechdrs_vaddr_order);
        gpa.free(self.sec_to_vaddr);
        gpa.free(self.sec_to_off);
    }

    // Get an identifier for the location within the file where additional data could be inserted.
    // TODO: consider if this function should also look at existing gaps to help find the cave which requires the minimal shift.
    pub fn get_cave_option(self: *const Self, wanted_size: u64, flags: std.elf.SectionHeaderFlags) Error!?SecEdge {
        const sechdr = self.coff.getSectionHeaders();
        var i = self.sechdrs_off_order.len;
        while (i > 0) {
            i -= 1;
            const sec_idx = self.sechdrs_off_order[i];
            if (sechdr[sec_idx].flags != flags) continue;
            // NOTE: this assumes you dont have an upper bound on possible memory address.
            if ((self.sec_to_vaddr[sec_idx] == (sechdr.len - 1)) or
                ((sechdr[sec_idx].virtual_address + sechdr[sec_idx].virtual_size + wanted_size) < sechdr[self.sec_to_vaddr[sec_idx] + 1])) return SecEdge{
                .sec_idx = sec_idx,
                .is_end = true,
            };
            const prev_sec_mem_bound = (if (self.sec_to_vaddr[sec_idx] == 0) 0 else (sechdr[self.sec_to_vaddr[sec_idx] - 1].virtual_address + sechdr[self.sec_to_vaddr[sec_idx] - 1].virtual_size));
            if (sechdr[sec_idx].virtual_address > (wanted_size + prev_sec_mem_bound)) return SecEdge{
                .sec_idx = sec_idx,
                .is_end = false,
            };
        }
        return null;
    }

    // NOTE: field changes must NOT change the memory order or offset order!
    // TODO: consider what to do when setting the segment which holds the phdrtable itself.
    fn set_sechdr_field(self: *Self, index: usize, val: u64, comptime field_name: []const u8) Error!void {
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
    pub fn create_cave(self: *Self, size: u64, edge: SecEdge) Error!void {
        // NOTE: moving around the pheader table sounds like a bad idea.
        std.debug.assert(edge.sec_idx != 0);
        const aligns = self.phdrs.items(Phdr64Fields.p_align);
        const offsets = self.phdrs.items(Phdr64Fields.p_offset);
        const vaddrs = self.phdrs.items(Phdr64Fields.p_vaddr);
        const paddrs = self.phdrs.items(Phdr64Fields.p_paddr);
        const fileszs = self.phdrs.items(Phdr64Fields.p_filesz);
        const memszs = self.phdrs.items(Phdr64Fields.p_memsz);
        const idx = self.phdrs_offset_order[self.top_off_segs[edge.sec_idx]];

        const new_offset: u64 = if (edge.is_end) offsets[idx] else self.calc_new_offset(edge.sec_idx, size);
        const first_adjust = if (edge.is_end) size else if (new_offset < offsets[idx]) size - (offsets[idx] - new_offset) else size + (new_offset - offsets[idx]);
        var needed_size = first_adjust;

        var top_idx = edge.sec_idx + 1;
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
            self.adjustments[top_idx - (edge.sec_idx + 1)] = needed_size;
        }
        var i = top_idx - (edge.sec_idx + 1);
        while (i > 0) {
            i -= 1;
            const top_index = i + edge.sec_idx + 1;
            const top_off_idx = self.top_off_segs[top_index];
            const top_seg_idx = self.phdrs_offset_order[top_off_idx];
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
        for (edge.sec_idx + 1..top_idx) |top_index| {
            const top_off_idx = self.top_off_segs[top_index];
            const top_seg_idx = self.phdrs_offset_order[top_off_idx];
            while ((sec_off_idx < self.shdrs_offset_order.len) and (shdr_offsets[self.shdrs_offset_order[sec_off_idx]] < (offsets[top_seg_idx] - self.adjustments[top_index - (edge.sec_idx + 1)]))) : (sec_off_idx += 1) {}
            while ((sec_off_idx < self.shdrs_offset_order.len) and (shdr_offsets[self.shdrs_offset_order[sec_off_idx]] < ((offsets[top_seg_idx] - self.adjustments[top_index - (edge.sec_idx + 1)]) + fileszs[top_seg_idx]))) : (sec_off_idx += 1) {
                const sec_idx = self.shdrs_offset_order[sec_off_idx];
                try self.set_shdr_field(sec_idx, shdr_offsets[sec_idx] + self.adjustments[top_index - (edge.sec_idx + 1)], "sh_offset");
            }
        }

        if (!edge.is_end) {
            const top_off_idx = self.top_off_segs[edge.sec_idx];
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

            try shift_forward(self.parse_source, offsets[idx], offsets[idx] + fileszs[idx], new_offset + size - offsets[idx]);
            try self.set_phdr_field(idx, vaddrs[idx] - size, "p_vaddr");
            // NOTE: not really sure about the following line.
            try self.set_phdr_field(idx, paddrs[idx] - size, "p_paddr");
            try self.set_phdr_field(idx, new_offset, "p_offset");
        } else {
            const top_off_idx = self.top_off_segs[edge.sec_idx];
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
        return std.math.order(context.lhs, context.self.phdrs.items(Phdr64Fields.p_vaddr)[context.self.phdrs_vaddr_order[rhs]]);
    }

    pub fn addr_to_off(self: *const Self, addr: u64) Error!u64 {
        const offsets = self.phdrs.items(Phdr64Fields.p_offset);
        const vaddrs = self.phdrs.items(Phdr64Fields.p_vaddr);
        const fileszs = self.phdrs.items(Phdr64Fields.p_filesz);
        const memszs = self.phdrs.items(Phdr64Fields.p_memsz);
        const containnig_idx = self.addr_to_idx(addr);
        if (!(addr < (vaddrs[containnig_idx] + memszs[containnig_idx]))) return Error.AddrNotMapped;
        const potenital_off = offsets[containnig_idx] + addr - vaddrs[containnig_idx];
        if (!(potenital_off < (offsets[containnig_idx] + fileszs[containnig_idx]))) return Error.NoMatchingOffset;
        return potenital_off;
    }

    pub fn addr_to_idx(self: *const Self, addr: u64) usize {
        return self.phdrs_vaddr_order[self.top_vaddr_segs[std.sort.lowerBound(usize, self.top_vaddr_segs, CompareContext{ .self = self, .lhs = addr + 1 }, addr_compareFn) - 1]];
    }

    fn off_compareFn(context: CompareContext, rhs: usize) std.math.Order {
        return std.math.order(context.lhs, context.self.phdrs.items(Phdr64Fields.p_offset)[context.self.phdrs_offset_order[rhs]]);
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
        return self.phdrs_offset_order[self.top_off_segs[std.sort.lowerBound(usize, self.top_off_segs, CompareContext{ .self = self, .lsh = off + 1 }, off_compareFn) - 1]];
    }
};

test "create_cave same output" {
    // NOTE: technically I could build the binary from source but I am unsure of a way to ensure that it will result in the exact same binary each time. (which would make the test flaky, since it might be that there is no viable code cave.).

    // check regular output.
    const no_cave_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{"./tests/hello_world"},
    });
    defer std.testing.allocator.free(no_cave_result.stdout);
    defer std.testing.allocator.free(no_cave_result.stderr);

    // create cave.
    // NOTE: need to put this in a block since the file must be closed before the next process can execute.
    {
        var f = try std.fs.cwd().openFile("./tests/hello_world", .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        const wanted_size = 0x1000;
        var elf_modder: ElfModder = try ElfModder.init(std.testing.allocator, &stream);
        defer elf_modder.deinit(std.testing.allocator);
        const option = (try elf_modder.get_cave_option(wanted_size, PType.PT_LOAD, PFlags{ .PF_X = true, .PF_R = true })).?;
        try elf_modder.create_cave(wanted_size, option);
    }

    // check output with a cave
    const cave_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{"./tests/hello_world"},
    });
    defer std.testing.allocator.free(cave_result.stdout);
    defer std.testing.allocator.free(cave_result.stderr);
    try std.testing.expect(cave_result.term.Exited == no_cave_result.term.Exited);
    try std.testing.expectEqualStrings(cave_result.stdout, no_cave_result.stdout);
    try std.testing.expectEqualStrings(cave_result.stderr, no_cave_result.stderr);
}
