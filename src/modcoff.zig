const std = @import("std");
const native_endian = @import("builtin").target.cpu.arch.endian();
const utils = @import("utils.zig");

fn off_lessThanFn(sechdrs: std.MultiArrayList(std.coff.SectionHeader), lhs: usize, rhs: usize) bool {
    const temp = sechdrs.items(SectionHeaderFields.pointer_to_raw_data);
    return temp[lhs] < temp[rhs];
}

// TODO: consider if this should have a similar logic, where segments which "contain" other segments come first.
fn vaddr_lessThanFn(sechdrs: std.MultiArrayList(std.coff.SectionHeader), lhs: usize, rhs: usize) bool {
    const temp = sechdrs.items(SectionHeaderFields.virtual_address);
    return temp[lhs] < temp[rhs];
}

pub const Error = error{
    AddrNotMapped,
    NoMatchingOffset,
    OffsetNotLoaded,
};

pub const SecEdge: type = struct {
    sec_idx: usize,
    is_end: bool,
};

const SectionHeaderFields = std.meta.FieldEnum(std.coff.SectionHeader);

pub const CoffModder: type = struct {
    coff: std.coff.Coff,
    sechdrs: std.MultiArrayList(std.coff.SectionHeader),
    sechdrs_off_order: []usize,
    sec_to_off: []usize,
    sechdrs_vaddr_order: []usize,
    sec_to_vaddr: []usize,
    adjustments: []usize,
    parse_source: *std.io.StreamSource,
    data: []const u8,

    const Self = @This();

    pub fn init(gpa: std.mem.Allocator, stream: *std.io.StreamSource) !Self {
        const data = try gpa.alloc(u8, try stream.getEndPos());
        errdefer gpa.free(data);
        const coff = try std.coff.Coff.init(data, false);
        var sechdrs = std.MultiArrayList(std.coff.SectionHeader){};
        errdefer sechdrs.deinit(gpa);
        const sechdrs_raw = coff.getSectionHeaders();
        try sechdrs.ensureTotalCapacity(gpa, sechdrs_raw.len);
        for (sechdrs_raw) |sechdr| {
            sechdrs.appendAssumeCapacity(sechdr);
        }
        const sechdrs_vaddr_order = try gpa.alloc(usize, sechdrs.len);
        errdefer gpa.free(sechdrs_vaddr_order);
        const sechdrs_off_order = try gpa.alloc(usize, sechdrs.len);
        errdefer gpa.free(sechdrs_off_order);
        for (0..sechdrs.len) |i| {
            sechdrs_vaddr_order[i] = i;
            sechdrs_off_order[i] = i;
        }
        std.sort.pdq(usize, sechdrs_vaddr_order, sechdrs, off_lessThanFn);
        std.sort.pdq(usize, sechdrs_off_order, sechdrs, vaddr_lessThanFn);
        const sec_to_off = try gpa.alloc(usize, sechdrs.len);
        errdefer gpa.free(sec_to_off);
        const sec_to_vaddr = try gpa.alloc(usize, sechdrs.len);
        errdefer gpa.free(sec_to_vaddr);
        for (sechdrs_off_order, sechdrs_vaddr_order, 0..) |off_idx, vaddr_idx, idx| {
            sec_to_off[off_idx] = idx;
            sec_to_vaddr[vaddr_idx] = idx;
        }
        return Self{
            .coff = coff,
            .sechdrs = sechdrs,
            .sechdrs_vaddr_order = sechdrs_vaddr_order,
            .sec_to_off = sec_to_off,
            .sechdrs_off_order = sechdrs_off_order,
            .sec_to_vaddr = sec_to_vaddr,
            .adjustments = try gpa.alloc(usize, sechdrs.len),
            .parse_source = stream,
            .data = data,
        };
    }

    pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
        gpa.free(self.sechdrs_off_order);
        gpa.free(self.sechdrs_vaddr_order);
        gpa.free(self.sec_to_vaddr);
        gpa.free(self.adjustments);
        gpa.free(self.sec_to_off);
        gpa.free(self.data);
        self.sechdrs.deinit(gpa);
    }

    // Get an identifier for the location within the file where additional data could be inserted.
    // TODO: consider if this function should also look at existing gaps to help find the cave which requires the minimal shift.
    pub fn get_cave_option(self: *const Self, wanted_size: u64, flags: std.coff.SectionHeaderFlags) !?SecEdge {
        const flagss = self.sechdrs.items(SectionHeaderFields.flags);
        const virtual_addresses = self.sechdrs.items(SectionHeaderFields.virtual_address);
        const virtual_sizes = self.sechdrs.items(SectionHeaderFields.virtual_size);
        var i = self.sechdrs_off_order.len;
        while (i > 0) {
            i -= 1;
            const sec_idx = self.sechdrs_off_order[i];
            if (flagss[sec_idx] != flags) continue;
            // NOTE: this assumes you dont have an upper bound on possible memory address.
            if ((self.sec_to_vaddr[sec_idx] == (self.sechdrs.len - 1)) or
                ((virtual_addresses[sec_idx] + virtual_sizes[sec_idx] + wanted_size) < virtual_addresses[self.sec_to_vaddr[sec_idx] + 1])) return SecEdge{
                .sec_idx = sec_idx,
                .is_end = true,
            };
            const prev_sec_mem_bound = (if (self.sec_to_vaddr[sec_idx] == 0) 0 else (virtual_addresses[self.sec_to_vaddr[sec_idx] - 1] + virtual_sizes[self.sec_to_vaddr[sec_idx] - 1]));
            if (virtual_addresses[sec_idx] > (wanted_size + prev_sec_mem_bound)) return SecEdge{
                .sec_idx = sec_idx,
                .is_end = false,
            };
        }
        return null;
    }

    fn calc_new_offset(self: *const Self, index: usize, size: u64) u64 {
        const pointers_to_raw_data = self.sechdrs.items(SectionHeaderFields.pointer_to_raw_data);
        const sizes_of_raw_data = self.sechdrs.items(SectionHeaderFields.size_of_raw_data);
        // TODO: add a check first for the case of an ending edge in which there already exists a large enough gap.
        // and for the case of a start edge whith enough space from the previous segment offset.
        const alignment = self.sechdrs.get(index).getAlignment() orelse 1;
        const align_offset = (pointers_to_raw_data[index] + (alignment - (size % alignment))) % alignment;
        const temp = self.sechdrs_off_order[self.sec_to_off[index] - 1];
        const prev_off_end = pointers_to_raw_data[temp] + sizes_of_raw_data[temp];
        std.debug.assert(prev_off_end <= pointers_to_raw_data[index]);
        const new_offset = if (pointers_to_raw_data[index] > (size + prev_off_end))
            (pointers_to_raw_data[index] - size)
        else
            (prev_off_end + (if ((prev_off_end % alignment) <= align_offset)
                (align_offset)
            else
                (alignment + align_offset)) - (prev_off_end % alignment));
        return new_offset;
    }

    // NOTE: field changes must NOT change the memory order or offset order!
    // TODO: consider what to do when setting the segment which holds the phdrtable itself.
    fn set_sechdr_field(self: *Self, index: usize, val: u64, comptime field_name: []const u8) !void {
        const coff_header = self.coff.getCoffHeader();
        const offset = self.coff.coff_header_offset + @sizeOf(std.coff.CoffHeader) + coff_header.size_of_optional_header;
        try self.parse_source.seekTo(offset + @sizeOf(std.coff.SectionHeader) * index);
        const T = std.meta.fieldInfo(std.coff.SectionHeader, @field(SectionHeaderFields, field_name)).type;
        const temp: T = @intCast(val);
        try self.parse_source.seekBy(@offsetOf(std.coff.SectionHeader, field_name));
        const temp2 = std.mem.toBytes(temp);
        std.debug.assert(try self.parse_source.write(&temp2) == @sizeOf(T));
        self.sechdrs.items(@field(SectionHeaderFields, field_name))[index] = @intCast(val);
    }

    // TODO: consider what happens when the original filesz and memsz are unequal.
    pub fn create_cave(self: *Self, size: u64, edge: SecEdge) !void {
        // NOTE: moving around the pheader table sounds like a bad idea.
        std.debug.assert(edge.sec_idx != 0);
        const pointers_to_raw_data = self.sechdrs.items(SectionHeaderFields.pointer_to_raw_data);
        const sizes_of_raw_data = self.sechdrs.items(SectionHeaderFields.size_of_raw_data);
        const virtual_addresses = self.sechdrs.items(SectionHeaderFields.virtual_address);
        const virtual_sizes = self.sechdrs.items(SectionHeaderFields.virtual_size);

        const offset = pointers_to_raw_data[edge.sec_idx];
        const new_offset: u64 = if (edge.is_end) offset else self.calc_new_offset(edge.sec_idx, size);
        const first_adjust = if (edge.is_end) size else if (new_offset < offset) size - (offset - new_offset) else size + (new_offset - offset);
        var needed_size = first_adjust;

        var off_idx = self.sec_to_off[edge.sec_idx] + 1;
        while (off_idx < self.sechdrs_off_order.len) : (off_idx += 1) {
            const sec_idx = self.sechdrs_off_order[off_idx];
            const prev_off_sec_idx = self.sechdrs_off_order[off_idx - 1];
            const existing_gap = pointers_to_raw_data[sec_idx] - (pointers_to_raw_data[prev_off_sec_idx] + sizes_of_raw_data[prev_off_sec_idx]);
            if (needed_size < existing_gap) break;
            needed_size -= existing_gap;
            if (self.sechdrs.get(sec_idx).getAlignment()) |alignment| {
                if ((needed_size % alignment) != 0) needed_size += alignment - (needed_size % alignment);
            }
            self.adjustments[off_idx - (self.sec_to_off[edge.sec_idx] + 1)] = needed_size;
        }
        var i = off_idx - (self.sec_to_off[edge.sec_idx] + 1);
        while (i > 0) {
            i -= 1;
            const curr_off_idx = i + (self.sec_to_off[edge.sec_idx] + 1);
            const sec_idx = self.sechdrs_off_order[curr_off_idx];
            try utils.shift_forward(self.parse_source, pointers_to_raw_data[sec_idx], pointers_to_raw_data[sec_idx] + sizes_of_raw_data[sec_idx], self.adjustments[i]);
            try self.set_sechdr_field(sec_idx, pointers_to_raw_data[sec_idx] + self.adjustments[i], "pointer_to_raw_data");
        }

        if (!edge.is_end) {
            try utils.shift_forward(self.parse_source, pointers_to_raw_data[edge.sec_idx], pointers_to_raw_data[edge.sec_idx] + sizes_of_raw_data[edge.sec_idx], new_offset + size - pointers_to_raw_data[edge.sec_idx]);
            try self.set_sechdr_field(edge.sec_idx, virtual_addresses[edge.sec_idx] + self.adjustments[i], "virtual_address");
            try self.set_sechdr_field(edge.sec_idx, new_offset, "pointer_to_raw_data");
        }
        try self.set_sechdr_field(edge.sec_idx, sizes_of_raw_data[edge.sec_idx] + size, "size_of_raw_data");
        try self.set_sechdr_field(edge.sec_idx, virtual_sizes[edge.sec_idx] + size, "virtual_size");
        // TODO: adjust sections as well (and maybe debug info?)
    }

    const CompareContext = struct {
        self: *const Self,
        lhs: u64,
    };

    fn addr_compareFn(context: CompareContext, rhs: usize) std.math.Order {
        return std.math.order(context.lhs, context.self.sechdrs.items(SectionHeaderFields.virtual_address)[context.self.sechdrs_vaddr_order[rhs]]);
    }

    pub fn addr_to_off(self: *const Self, addr: u64) !u64 {
        const pointers_to_raw_data = self.sechdrs.items(SectionHeaderFields.pointer_to_raw_data);
        const virtual_addresses = self.sechdrs.items(SectionHeaderFields.virtual_address);
        const sizes_of_raw_data = self.sechdrs.items(SectionHeaderFields.size_of_raw_data);
        const virtual_sizes = self.sechdrs.items(SectionHeaderFields.virtual_size);
        const containnig_idx = self.addr_to_idx(addr);
        if (!(addr < (virtual_addresses[containnig_idx] + virtual_sizes[containnig_idx]))) return Error.AddrNotMapped;
        const potenital_off = pointers_to_raw_data[containnig_idx] + addr - virtual_addresses[containnig_idx];
        if (!(potenital_off < (pointers_to_raw_data[containnig_idx] + sizes_of_raw_data[containnig_idx]))) return Error.NoMatchingOffset;
        return potenital_off;
    }

    pub fn addr_to_idx(self: *const Self, addr: u64) usize {
        return self.sechdrs_vaddr_order[std.sort.lowerBound(usize, self.sechdrs_vaddr_order, CompareContext{ .self = self, .lhs = addr + 1 }, addr_compareFn) - 1];
    }

    fn off_compareFn(context: CompareContext, rhs: usize) std.math.Order {
        return std.math.order(context.lhs, context.self.sechdrs.items(SectionHeaderFields.pointer_to_raw_data)[context.self.sechdrs_off_order[rhs]]);
    }

    pub fn off_to_addr(self: *const Self, off: u64) !u64 {
        const pointers_to_raw_data = self.sechdrs.items(SectionHeaderFields.pointer_to_raw_data);
        const virtual_addresses = self.sechdrs.items(SectionHeaderFields.virtual_address);
        const sizes_of_raw_data = self.sechdrs.items(SectionHeaderFields.size_of_raw_data);
        const virtual_sizes = self.sechdrs.items(SectionHeaderFields.virtual_size);
        const containnig_idx = self.off_to_idx(off);
        if (!(off < (pointers_to_raw_data[containnig_idx] + sizes_of_raw_data[containnig_idx]))) return Error.OffsetNotLoaded;
        std.debug.assert(virtual_sizes[containnig_idx] >= sizes_of_raw_data[containnig_idx]);
        return virtual_addresses[containnig_idx] + off - pointers_to_raw_data[containnig_idx];
    }

    pub fn off_to_idx(self: *const Self, off: u64) usize {
        return self.sechdrs_off_order[std.sort.lowerBound(usize, self.sechdrs_off_order, CompareContext{ .self = self, .lsh = off + 1 }, off_compareFn) - 1];
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
        const option = (try coff_modder.get_cave_option(wanted_size, std.coff.SectionHeaderFlags{ .MEM_READ = 1, .MEM_EXECUTE = 1 })).?;
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
