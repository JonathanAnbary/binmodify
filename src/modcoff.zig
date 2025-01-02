const std = @import("std");
const native_endian = @import("builtin").target.cpu.arch.endian();
const utils = @import("utils.zig");

fn off_lessThanFn(sechdrs: []align(1) const std.coff.SectionHeader, lhs: usize, rhs: usize) bool {
    return sechdrs[lhs].pointer_to_raw_data < sechdrs[rhs].pointer_to_raw_data;
}

// TODO: consider if this should have a similar logic, where segments which "contain" other segments come first.
fn addr_lessThanFn(sechdrs: []align(1) const std.coff.SectionHeader, lhs: usize, rhs: usize) bool {
    return sechdrs[lhs].virtual_address < sechdrs[rhs].virtual_address;
}

pub const Error = error{
    AddrNotMapped,
    NoMatchingOffset,
    OffsetNotLoaded,
    NoCaveOption,
} || std.coff.CoffError;

pub const SecEdge: type = struct {
    sec_idx: usize,
    is_end: bool,
};

const SectionHeaderFields = std.meta.FieldEnum(std.coff.SectionHeader);

pub const CoffModder: type = struct {
    coff: std.coff.Coff,
    sechdrs_off_order: []usize,
    sec_to_off: []usize,
    sechdrs_addr_order: []usize,
    sec_to_addr: []usize,
    adjustments: []usize,
    parse_source: *std.io.StreamSource,
    data: []u8,

    const Self = @This();

    pub fn init(gpa: std.mem.Allocator, stream: *std.io.StreamSource) !Self {
        const data = try gpa.alloc(u8, try stream.getEndPos());
        errdefer gpa.free(data);
        try stream.seekTo(0);
        std.debug.assert(try stream.read(data) == data.len);
        const coff = try std.coff.Coff.init(data, false);
        const sechdrs = coff.getSectionHeaders();
        const sechdrs_addr_order = try gpa.alloc(usize, sechdrs.len);
        errdefer gpa.free(sechdrs_addr_order);
        const sechdrs_off_order = try gpa.alloc(usize, sechdrs.len);
        errdefer gpa.free(sechdrs_off_order);
        for (0..sechdrs.len) |i| {
            sechdrs_addr_order[i] = i;
            sechdrs_off_order[i] = i;
        }
        std.sort.pdq(usize, sechdrs_addr_order, sechdrs, off_lessThanFn);
        std.sort.pdq(usize, sechdrs_off_order, sechdrs, addr_lessThanFn);
        const sec_to_off = try gpa.alloc(usize, sechdrs.len);
        errdefer gpa.free(sec_to_off);
        const sec_to_addr = try gpa.alloc(usize, sechdrs.len);
        errdefer gpa.free(sec_to_addr);
        for (sechdrs_off_order, sechdrs_addr_order, 0..) |off_idx, addr_idx, idx| {
            sec_to_off[off_idx] = idx;
            sec_to_addr[addr_idx] = idx;
        }
        return Self{
            .coff = coff,
            .sechdrs_addr_order = sechdrs_addr_order,
            .sec_to_off = sec_to_off,
            .sechdrs_off_order = sechdrs_off_order,
            .sec_to_addr = sec_to_addr,
            .adjustments = try gpa.alloc(usize, sechdrs.len),
            .parse_source = stream,
            .data = data,
        };
    }

    pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
        gpa.free(self.sechdrs_off_order);
        gpa.free(self.sechdrs_addr_order);
        gpa.free(self.sec_to_addr);
        gpa.free(self.adjustments);
        gpa.free(self.sec_to_off);
        gpa.free(self.data);
    }

    // Get an identifier for the location within the file where additional data could be inserted.
    // TODO: consider if this function should also look at existing gaps to help find the cave which requires the minimal shift.
    pub fn get_cave_option(self: *const Self, wanted_size: u64, flags: utils.FileRangeFlags) !?SecEdge {
        const sechdrs = self.coff.getSectionHeaders();
        var i = self.sechdrs_off_order.len;
        std.debug.print("\nlooking for flags {}\n", .{flags});
        while (i > 0) {
            i -= 1;
            const sec_idx = self.sechdrs_off_order[i];
            const sec_flags = utils.FileRangeFlags{ .read = sechdrs[sec_idx].flags.MEM_READ == 1, .write = sechdrs[sec_idx].flags.MEM_WRITE == 1, .execute = sechdrs[sec_idx].flags.MEM_EXECUTE == 1 };
            std.debug.print("sec_idx {} has flags {}\n", .{ sec_idx, sec_flags });
            if (sec_flags != flags) continue;
            std.debug.print("sec_end_addr = {x}\n", .{sechdrs[sec_idx].virtual_address + sechdrs[sec_idx].virtual_size + wanted_size});
            std.debug.print("next sec start = {x}\n", .{if (self.sec_to_addr[sec_idx] == (sechdrs.len - 1)) std.math.maxInt(u64) else @as(usize, @intCast(sechdrs[self.sec_to_addr[sec_idx] + 1].virtual_address))});
            // NOTE: this assumes you dont have an upper bound on possible memory address.
            if ((self.sec_to_addr[sec_idx] == (sechdrs.len - 1)) or
                ((sechdrs[sec_idx].virtual_address + sechdrs[sec_idx].virtual_size + wanted_size) < sechdrs[self.sec_to_addr[sec_idx] + 1].virtual_address)) return SecEdge{
                .sec_idx = sec_idx,
                .is_end = true,
            };
            // NOTE: not doing start caves since I am not sure how to resolve the alignment requirements of section start address.
            // std.debug.print("sec_start_addr = {x}\n", .{sechdrs[sec_idx].virtual_address});
            // const prev_sec_mem_bound = (if (self.sec_to_addr[sec_idx] == 0) 0 else (sechdrs[self.sec_to_addr[sec_idx] - 1].virtual_address + sechdrs[self.sec_to_addr[sec_idx] - 1].virtual_size));
            // std.debug.print("prev sec end = {x}\n", .{prev_sec_mem_bound});
            // if (sechdrs[sec_idx].virtual_address > (wanted_size + prev_sec_mem_bound)) return SecEdge{
            //     .sec_idx = sec_idx,
            //     .is_end = false,
            // };
        }
        return null;
    }

    fn calc_new_offset(self: *const Self, index: usize, size: u64) u64 {
        // TODO: add a check first for the case of an ending edge in which there already exists a large enough gap.
        // and for the case of a start edge whith enough space from the previous segment offset.
        const sechdrs = self.coff.getSectionHeaders();
        const hdr = self.coff.getOptionalHeader();
        const file_alignment = switch (hdr.magic) {
            std.coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => self.coff.getOptionalHeader32().file_alignment,
            std.coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => self.coff.getOptionalHeader64().file_alignment,
            else => unreachable, // We assume we have validated the header already
        };

        const align_offset = (sechdrs[index].pointer_to_raw_data + (file_alignment - (size % file_alignment))) % file_alignment;
        const temp = self.sechdrs_off_order[self.sec_to_off[index] - 1];
        const prev_off_end = sechdrs[temp].pointer_to_raw_data + sechdrs[temp].size_of_raw_data;
        std.debug.assert(prev_off_end <= sechdrs[index].pointer_to_raw_data);
        const new_offset = if (sechdrs[index].pointer_to_raw_data > (size + prev_off_end))
            (sechdrs[index].pointer_to_raw_data - size)
        else
            (prev_off_end + (if ((prev_off_end % file_alignment) <= align_offset)
                (align_offset)
            else
                (file_alignment + align_offset)) - (prev_off_end % file_alignment));
        return new_offset;
    }

    // NOTE: field changes must NOT change the memory order or offset order!
    // TODO: consider what to do when setting the segment which holds the phdrtable itself.
    fn set_sechdr_field(self: *Self, index: usize, val: u64, comptime field_name: []const u8) !void {
        const sechdrs = self.coff.getSectionHeaders();
        std.debug.print("setting {s}[{}] from {x} to {x}\n", .{ field_name, index, @field(sechdrs[index], field_name), val });
        const coff_header = self.coff.getCoffHeader();
        const offset = self.coff.coff_header_offset + @sizeOf(std.coff.CoffHeader) + coff_header.size_of_optional_header;
        try self.parse_source.seekTo(offset + @sizeOf(std.coff.SectionHeader) * index);
        const T = std.meta.fieldInfo(std.coff.SectionHeader, @field(SectionHeaderFields, field_name)).type;
        const temp: T = @intCast(val);
        try self.parse_source.seekBy(@offsetOf(std.coff.SectionHeader, field_name));
        const temp2 = std.mem.toBytes(temp);
        std.debug.assert(try self.parse_source.write(&temp2) == @sizeOf(T));
        // TODO: look at whether or not this breaks the consts guarantees expected by std.coff.
        std.mem.copyForwards(u8, self.data[offset + @sizeOf(std.coff.SectionHeader) * index + @offsetOf(std.coff.SectionHeader, field_name) ..][0..temp2.len], &temp2);
        // self.sechdrs.items(@field(SectionHeaderFields, field_name))[index] = @intCast(val);
    }

    pub fn create_cave(self: *Self, size: u64, edge: SecEdge) !void {
        const sechdrs = self.coff.getSectionHeaders();
        const hdr = self.coff.getOptionalHeader();
        const file_alignment = switch (hdr.magic) {
            std.coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => self.coff.getOptionalHeader32().file_alignment,
            std.coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => self.coff.getOptionalHeader64().file_alignment,
            else => unreachable, // We assume we have validated the header already
        };

        const offset = sechdrs[edge.sec_idx].pointer_to_raw_data;
        const new_offset: u64 = if (edge.is_end) offset else self.calc_new_offset(edge.sec_idx, size);
        const first_adjust = if (edge.is_end) size else if (new_offset < offset) size - (offset - new_offset) else size + (new_offset - offset);
        var needed_size = first_adjust;

        var off_idx = self.sec_to_off[edge.sec_idx] + 1;
        while (off_idx < self.sechdrs_off_order.len) : (off_idx += 1) {
            const sec_idx = self.sechdrs_off_order[off_idx];
            const prev_off_sec_idx = self.sechdrs_off_order[off_idx - 1];
            // TODO: should consider calculating the padding and treating it as overwritable.
            const existing_gap = sechdrs[sec_idx].pointer_to_raw_data - (sechdrs[prev_off_sec_idx].pointer_to_raw_data + sechdrs[prev_off_sec_idx].size_of_raw_data);
            if (needed_size < existing_gap) break;
            needed_size -= existing_gap;
            if ((needed_size % file_alignment) != 0) needed_size += file_alignment - (needed_size % file_alignment);
            self.adjustments[off_idx - (self.sec_to_off[edge.sec_idx] + 1)] = needed_size;
        }
        var i = off_idx - (self.sec_to_off[edge.sec_idx] + 1);
        while (i > 0) {
            i -= 1;
            const curr_off_idx = i + (self.sec_to_off[edge.sec_idx] + 1);
            const sec_idx = self.sechdrs_off_order[curr_off_idx];
            try utils.shift_forward(self.parse_source, sechdrs[sec_idx].pointer_to_raw_data, sechdrs[sec_idx].pointer_to_raw_data + sechdrs[sec_idx].size_of_raw_data, self.adjustments[i]);
            try self.set_sechdr_field(sec_idx, sechdrs[sec_idx].pointer_to_raw_data + self.adjustments[i], "pointer_to_raw_data");
        }

        if (!edge.is_end) {
            try utils.shift_forward(self.parse_source, sechdrs[edge.sec_idx].pointer_to_raw_data, sechdrs[edge.sec_idx].pointer_to_raw_data + sechdrs[edge.sec_idx].size_of_raw_data, new_offset + size - sechdrs[edge.sec_idx].pointer_to_raw_data);
            try self.set_sechdr_field(edge.sec_idx, sechdrs[edge.sec_idx].virtual_address + self.adjustments[i], "virtual_address");
            try self.set_sechdr_field(edge.sec_idx, new_offset, "pointer_to_raw_data");
        }
        try self.set_sechdr_field(edge.sec_idx, sechdrs[edge.sec_idx].size_of_raw_data + size, "size_of_raw_data");
        try self.set_sechdr_field(edge.sec_idx, sechdrs[edge.sec_idx].virtual_size + size, "virtual_size");
        // TODO: adjust sections as well (and maybe debug info?)
    }

    const CompareContext = struct {
        self: *const Self,
        lhs: u64,
    };

    fn addr_compareFn(context: CompareContext, rhs: usize) std.math.Order {
        return std.math.order(context.lhs, context.self.coff.getSectionHeaders()[context.self.sechdrs_addr_order[rhs]].virtual_address);
    }

    pub fn addr_to_off(self: *const Self, addr: u64) !u64 {
        const sechdrs = self.coff.getSectionHeaders();
        const image_base = self.coff.getImageBase();
        const normalized_addr = if (addr < image_base) return Error.AddrNotMapped else addr - image_base;
        const containnig_idx = self.addr_to_idx(normalized_addr);
        if (!(normalized_addr < (sechdrs[containnig_idx].virtual_address + sechdrs[containnig_idx].virtual_address))) return Error.AddrNotMapped;
        const potenital_off = sechdrs[containnig_idx].pointer_to_raw_data + normalized_addr - sechdrs[containnig_idx].virtual_address;
        if (!(potenital_off < (sechdrs[containnig_idx].pointer_to_raw_data + sechdrs[containnig_idx].size_of_raw_data))) return Error.NoMatchingOffset;
        return potenital_off;
    }

    fn addr_to_idx(self: *const Self, addr: u64) usize {
        return self.sechdrs_addr_order[std.sort.lowerBound(usize, self.sechdrs_addr_order, CompareContext{ .self = self, .lhs = addr + 1 }, addr_compareFn) - 1];
    }

    fn off_compareFn(context: CompareContext, rhs: usize) std.math.Order {
        return std.math.order(context.lhs, context.self.coff.getSectionHeaders()[context.self.sechdrs_off_order[rhs]].pointer_to_raw_data);
    }

    pub fn off_to_addr(self: *const Self, off: u64) !u64 {
        const sechdrs = self.coff.getSectionHeaders();
        const containnig_idx = self.off_to_idx(off);
        if (!(off < (sechdrs[containnig_idx].pointer_to_raw_data + sechdrs[containnig_idx].size_of_raw_data))) return Error.OffsetNotLoaded;
        std.debug.print("containnig_idx = {}\n", .{containnig_idx});
        std.debug.print("virtual_size = {x}, size_of_raw_data = {x}\n", .{ sechdrs[containnig_idx].virtual_size, sechdrs[containnig_idx].size_of_raw_data });
        const hdr = self.coff.getOptionalHeader();
        const file_alignment = switch (hdr.magic) {
            std.coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => self.coff.getOptionalHeader32().file_alignment,
            std.coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => self.coff.getOptionalHeader64().file_alignment,
            else => unreachable, // We assume we have validated the header already
        };

        std.debug.assert((sechdrs[containnig_idx].virtual_size >= sechdrs[containnig_idx].size_of_raw_data) or ((sechdrs[containnig_idx].size_of_raw_data - sechdrs[containnig_idx].virtual_size) < file_alignment));
        return self.coff.getImageBase() + sechdrs[containnig_idx].virtual_address + off - sechdrs[containnig_idx].pointer_to_raw_data;
    }

    fn off_to_idx(self: *const Self, off: u64) usize {
        return self.sechdrs_off_order[std.sort.lowerBound(usize, self.sechdrs_off_order, CompareContext{ .self = self, .lhs = off + 1 }, off_compareFn) - 1];
    }

    pub fn cave_to_off(self: Self, cave: SecEdge, size: u64) u64 {
        return self.coff.getSectionHeaders()[cave.sec_idx].pointer_to_raw_data + if (cave.is_end) self.coff.getSectionHeaders()[cave.sec_idx].size_of_raw_data - size else 0;
    }
};

test "create_cave same output" {
    // NOTE: technically I could build the binary from source but I am unsure of a way to ensure that it will result in the exact same binary each time. (which would make the test flaky, since it might be that there is no viable code cave.).

    const test_path = "./tests/hello_world.exe";
    const test_with_cave = "./create_cave_same_output_coff.exe";
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
        var f = try std.fs.cwd().openFile(test_with_cave, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        const wanted_size = 0x1000;
        var coff_modder: CoffModder = try CoffModder.init(std.testing.allocator, &stream);
        defer coff_modder.deinit(std.testing.allocator);
        const option = (try coff_modder.get_cave_option(wanted_size, utils.FileRangeFlags{ .read = true, .execute = true })) orelse return Error.NoCaveOption;
        try coff_modder.create_cave(wanted_size, option);
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
