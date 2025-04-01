const std = @import("std");

const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();

const shift = @import("../shift.zig");
const FileRangeFlags = @import("../file_range_flags.zig").FileRangeFlags;

const Parsed = @import("Parsed.zig");

fn off_lessThanFn(sechdrs: []const std.coff.SectionHeader, lhs: usize, rhs: usize) bool {
    return sechdrs[lhs].pointer_to_raw_data < sechdrs[rhs].pointer_to_raw_data;
}

// TODO: consider if this should have a similar logic, where segments which "contain" other segments come first.
fn addr_lessThanFn(sechdrs: []const std.coff.SectionHeader, lhs: usize, rhs: usize) bool {
    return sechdrs[lhs].virtual_address < sechdrs[rhs].virtual_address;
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
} || shift.Error || std.io.StreamSource.ReadError || std.io.StreamSource.WriteError || std.io.StreamSource.SeekError || std.io.StreamSource.GetSeekPosError || std.coff.CoffError || std.mem.Allocator.Error;

pub const SecEdge: type = struct {
    sec_idx: usize,
    is_end: bool,
};

pub const EdgeType = SecEdge;

const SectionHeaderFields = std.meta.FieldEnum(std.coff.SectionHeader);

const PartialHeader = struct {
    file_alignment: u32,
    image_base: u64,
    coff_header_offset: usize,
    size_of_optional_header: u16,
};

const Modder = @This();

header: PartialHeader,
sechdrs: []std.coff.SectionHeader,
off_sort: [*]usize,
sec_to_off: [*]usize,
addr_sort: [*]usize,
sec_to_addr: [*]usize,
adjustments: [*]usize,

pub fn init(gpa: std.mem.Allocator, parsed_source: *const Parsed, parse_source: anytype) Error!Modder {
    _ = parse_source;
    const sechdrs = try parsed_source.coff.getSectionHeadersAlloc(gpa);
    errdefer gpa.free(sechdrs);
    const addr_sort = try gpa.alloc(usize, sechdrs.len);
    errdefer gpa.free(addr_sort);
    const off_sort = try gpa.alloc(usize, sechdrs.len);
    errdefer gpa.free(off_sort);
    for (0..sechdrs.len) |i| {
        addr_sort[i] = i;
        off_sort[i] = i;
    }
    std.sort.pdq(usize, addr_sort, sechdrs, off_lessThanFn);
    std.sort.pdq(usize, off_sort, sechdrs, addr_lessThanFn);
    const sec_to_off = try gpa.alloc(usize, sechdrs.len);
    errdefer gpa.free(sec_to_off);
    const sec_to_addr = try gpa.alloc(usize, sechdrs.len);
    errdefer gpa.free(sec_to_addr);
    for (off_sort, addr_sort, 0..) |off_idx, addr_idx, idx| {
        sec_to_off[off_idx] = idx;
        sec_to_addr[addr_idx] = idx;
    }
    const optional_header = parsed_source.coff.getOptionalHeader();

    // std.debug.print("\n", .{});
    // for (sechdrs) |*sechdr| {
    //     std.debug.print("{X} - {X} - {X} - {X}\n", .{ sechdr.virtual_address, sechdr.virtual_size, sechdr.pointer_to_raw_data, sechdr.size_of_raw_data });
    // }

    return Modder{
        .header = .{
            .file_alignment = switch (optional_header.magic) {
                std.coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => parsed_source.coff.getOptionalHeader64().file_alignment,
                std.coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => parsed_source.coff.getOptionalHeader32().file_alignment,
                else => return Error.InvalidOptionalHeaderMagic,
            },
            .image_base = parsed_source.coff.getImageBase(),
            .coff_header_offset = parsed_source.coff.coff_header_offset,
            .size_of_optional_header = parsed_source.coff.getCoffHeader().size_of_optional_header,
        },
        .sechdrs = sechdrs,
        .addr_sort = addr_sort.ptr,
        .sec_to_off = sec_to_off.ptr,
        .off_sort = off_sort.ptr,
        .sec_to_addr = sec_to_addr.ptr,
        .adjustments = (try gpa.alloc(usize, sechdrs.len)).ptr,
    };
}

pub fn deinit(self: *Modder, gpa: std.mem.Allocator) void {
    gpa.free(self.adjustments[0..self.sechdrs.len]);
    gpa.free(self.sec_to_addr[0..self.sechdrs.len]);
    gpa.free(self.sec_to_off[0..self.sechdrs.len]);
    gpa.free(self.off_sort[0..self.sechdrs.len]);
    gpa.free(self.addr_sort[0..self.sechdrs.len]);
    gpa.free(self.sechdrs);
}

// Get an identifier for the location within the file where additional data could be inserted.
// TODO: consider if this function should also look at existing gaps to help find the cave which requires the minimal shift.
pub fn get_cave_option(self: *const Modder, wanted_size: u64, flags: FileRangeFlags) Error!?SecEdge {
    var i = self.sechdrs.len;
    while (i > 0) {
        i -= 1;
        const sec_idx = self.off_sort[i];
        const sec_flags = FileRangeFlags{ .read = self.sechdrs[sec_idx].flags.MEM_READ == 1, .write = self.sechdrs[sec_idx].flags.MEM_WRITE == 1, .execute = self.sechdrs[sec_idx].flags.MEM_EXECUTE == 1 };
        if (sec_flags != flags) continue;
        // NOTE: this assumes you dont have an upper bound on possible memory address.
        if ((self.sec_to_addr[sec_idx] == (self.sechdrs.len - 1)) or
            ((self.sechdrs[sec_idx].virtual_address + self.sechdrs[sec_idx].virtual_size + wanted_size) < self.sechdrs[self.sec_to_addr[sec_idx] + 1].virtual_address)) return SecEdge{
            .sec_idx = sec_idx,
            .is_end = true,
        };
        // NOTE: not doing start caves since I am not sure how to resolve the alignment requirements of section start address.
        const prev_sec_mem_bound = (if (self.sec_to_addr[sec_idx] == 0) 0 else (self.sechdrs[self.sec_to_addr[sec_idx] - 1].virtual_address + self.sechdrs[self.sec_to_addr[sec_idx] - 1].virtual_size));
        if (self.sechdrs[sec_idx].virtual_address > (wanted_size + prev_sec_mem_bound)) return SecEdge{
            .sec_idx = sec_idx,
            .is_end = false,
        };
    }
    return null;
}

fn calc_new_offset(self: *const Modder, index: usize, size: u64) Error!u64 {
    // TODO: add a check first for the case of an ending edge in which there already exists a large enough gap.
    // and for the case of a start edge whith enough space from the previous segment offset.
    const align_offset = (self.sechdrs[index].pointer_to_raw_data + (self.header.file_alignment - (size % self.header.file_alignment))) % self.header.file_alignment;
    const prev_off_end = blk: {
        const off_idx = self.sec_to_off[index];
        if (self.sec_to_off[index] > 0) {
            const temp = self.off_sort[off_idx - 1];
            break :blk self.sechdrs[temp].pointer_to_raw_data + self.sechdrs[temp].size_of_raw_data;
        } else break :blk 0;
    };
    if (prev_off_end > self.sechdrs[index].pointer_to_raw_data) return Error.IntersectingFileRanges;
    const new_offset = if (self.sechdrs[index].pointer_to_raw_data > (size + prev_off_end))
        (self.sechdrs[index].pointer_to_raw_data - size)
    else
        (prev_off_end + (if ((prev_off_end % self.header.file_alignment) <= align_offset)
            (align_offset)
        else
            (self.header.file_alignment + align_offset)) - (prev_off_end % self.header.file_alignment));
    return new_offset;
}

// NOTE: field changes must NOT change the memory order or offset order!
// TODO: consider what to do when setting the segment which holds the phdrtable itself.
fn set_sechdr_field(self: *Modder, index: usize, val: u64, comptime field_name: []const u8, parse_source: anytype) Error!void {
    const offset = self.header.coff_header_offset + @sizeOf(std.coff.CoffHeader) + self.header.size_of_optional_header;
    try parse_source.seekTo(offset + @sizeOf(std.coff.SectionHeader) * index);
    const T = std.meta.fieldInfo(std.coff.SectionHeader, @field(SectionHeaderFields, field_name)).type;
    const temp: T = @intCast(val);
    try parse_source.seekBy(@offsetOf(std.coff.SectionHeader, field_name));
    const temp2 = std.mem.toBytes(temp);
    if (try parse_source.write(&temp2) != @sizeOf(T)) return Error.UnexpectedEof;
    @field(self.sechdrs[index], field_name) = @intCast(val);
}

pub fn create_cave(self: *Modder, size: u64, edge: SecEdge, parse_source: anytype) Error!void {
    const offset = self.sechdrs[edge.sec_idx].pointer_to_raw_data;
    const new_offset: u64 = if (edge.is_end) offset else try self.calc_new_offset(edge.sec_idx, size);
    const first_adjust = if (edge.is_end) size else if (new_offset < offset) size - (offset - new_offset) else size + (new_offset - offset);
    var needed_size = first_adjust;

    var off_idx = self.sec_to_off[edge.sec_idx] + 1;
    while (off_idx < self.sechdrs.len) : (off_idx += 1) {
        const sec_idx = self.off_sort[off_idx];
        const prev_off_sec_idx = self.off_sort[off_idx - 1];
        // TODO: should consider calculating the padding and treating it as overwritable.
        const existing_gap = self.sechdrs[sec_idx].pointer_to_raw_data - (self.sechdrs[prev_off_sec_idx].pointer_to_raw_data + self.sechdrs[prev_off_sec_idx].size_of_raw_data);
        if (needed_size < existing_gap) break;
        needed_size -= existing_gap;
        if ((needed_size % self.header.file_alignment) != 0) needed_size += self.header.file_alignment - (needed_size % self.header.file_alignment);
        self.adjustments[off_idx - (self.sec_to_off[edge.sec_idx] + 1)] = needed_size;
    }
    var i = off_idx - (self.sec_to_off[edge.sec_idx] + 1);
    while (i > 0) {
        i -= 1;
        const curr_off_idx = i + (self.sec_to_off[edge.sec_idx] + 1);
        const sec_idx = self.off_sort[curr_off_idx];
        try shift.shift_forward(parse_source, self.sechdrs[sec_idx].pointer_to_raw_data, self.sechdrs[sec_idx].pointer_to_raw_data + self.sechdrs[sec_idx].size_of_raw_data, self.adjustments[i]);
        try self.set_sechdr_field(sec_idx, self.sechdrs[sec_idx].pointer_to_raw_data + self.adjustments[i], "pointer_to_raw_data", parse_source);
    }

    if (!edge.is_end) {
        try shift.shift_forward(parse_source, self.sechdrs[edge.sec_idx].pointer_to_raw_data, self.sechdrs[edge.sec_idx].pointer_to_raw_data + self.sechdrs[edge.sec_idx].size_of_raw_data, new_offset + size - self.sechdrs[edge.sec_idx].pointer_to_raw_data);
        try self.set_sechdr_field(edge.sec_idx, self.sechdrs[edge.sec_idx].virtual_address + self.adjustments[i], "virtual_address", parse_source);
        try self.set_sechdr_field(edge.sec_idx, new_offset, "pointer_to_raw_data", parse_source);
    }
    try self.set_sechdr_field(edge.sec_idx, self.sechdrs[edge.sec_idx].size_of_raw_data + size, "size_of_raw_data", parse_source);
    try self.set_sechdr_field(edge.sec_idx, self.sechdrs[edge.sec_idx].virtual_size + size, "virtual_size", parse_source);
    // TODO: might need to adjust some more things.
}

const CompareContext = struct {
    self: *const Modder,
    lhs: u64,
};

fn addr_compareFn(context: CompareContext, rhs: usize) std.math.Order {
    return std.math.order(context.lhs, context.self.sechdrs[context.self.addr_sort[rhs]].virtual_address);
}

pub fn addr_to_off(self: *const Modder, addr: u64) Error!u64 {
    const normalized_addr = if (addr < self.header.image_base) return Error.AddrNotMapped else addr - self.header.image_base;
    const containnig_idx = try self.addr_to_idx(normalized_addr);
    if (!(normalized_addr < (self.sechdrs[containnig_idx].virtual_address + self.sechdrs[containnig_idx].virtual_size))) return Error.AddrNotMapped;
    const potenital_off = self.sechdrs[containnig_idx].pointer_to_raw_data + normalized_addr - self.sechdrs[containnig_idx].virtual_address;
    if (!(potenital_off < (self.sechdrs[containnig_idx].pointer_to_raw_data + self.sechdrs[containnig_idx].size_of_raw_data))) return Error.NoMatchingOffset;
    return potenital_off;
}

fn addr_to_idx(self: *const Modder, addr: u64) !usize {
    // const temp = std.sort.lowerBound(usize, self.addr_sort[0..self.sechdrs.len], CompareContext{ .self = self, .lhs = addr + 1 }, addr_compareFn);
    // std.debug.print("\nself.sechdrs[self.addr_sort[temp]].virtual_address = {X}\n", .{self.sechdrs[self.addr_sort[temp]].virtual_address});
    // std.debug.print("addr = {X}\n", .{addr});
    const lower_bound = std.sort.lowerBound(usize, self.addr_sort[0..self.sechdrs.len], CompareContext{ .self = self, .lhs = addr + 1 }, addr_compareFn);
    if (lower_bound == 0) return Error.AddrNotMapped;
    return self.addr_sort[lower_bound - 1];
}

fn off_compareFn(context: CompareContext, rhs: usize) std.math.Order {
    return std.math.order(context.lhs, context.self.sechdrs[context.self.off_sort[rhs]].pointer_to_raw_data);
}

pub fn off_to_addr(self: *const Modder, off: u64) Error!u64 {
    const containnig_idx = self.off_to_idx(off);
    if (!(off < (self.sechdrs[containnig_idx].pointer_to_raw_data + self.sechdrs[containnig_idx].size_of_raw_data))) return Error.OffsetNotLoaded;
    if ((self.sechdrs[containnig_idx].virtual_size < self.sechdrs[containnig_idx].size_of_raw_data) and ((self.sechdrs[containnig_idx].size_of_raw_data - self.sechdrs[containnig_idx].virtual_size) >= self.header.file_alignment)) return Error.VirtualSizeLessThenFileSize;
    return self.header.image_base + self.sechdrs[containnig_idx].virtual_address + off - self.sechdrs[containnig_idx].pointer_to_raw_data;
}

fn off_to_idx(self: *const Modder, off: u64) usize {
    return self.off_sort[std.sort.lowerBound(usize, self.off_sort[0..self.sechdrs.len], CompareContext{ .self = self, .lhs = off + 1 }, off_compareFn) - 1];
}

pub fn cave_to_off(self: Modder, cave: SecEdge, size: u64) u64 {
    return self.sechdrs[cave.sec_idx].pointer_to_raw_data + if (cave.is_end) self.sechdrs[cave.sec_idx].size_of_raw_data - size else 0;
}

test "create cave same output" {
    const test_src_path = "./tests/hello_world.zig";
    const test_with_cave_prefix = "./create_cave_same_output_coff";
    const native_compile_path = "./coff_cave_hello_world";
    const cwd: std.fs.Dir = std.fs.cwd();
    const optimzes = &.{ "ReleaseSmall", "ReleaseFast", "Debug" }; // ReleaseSafe seems to be generated without any large caves.
    const targets = &.{ "x86_64-windows", "x86-windows" };

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

    std.debug.print("\n", .{});
    inline for (optimzes) |optimize| {
        inline for (targets) |target| {
            const test_with_cave_filename = test_with_cave_prefix ++ target ++ optimize ++ ".exe";
            std.debug.print("test_with_cave_filename = {s}\n", .{test_with_cave_filename});
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
                const wanted_size = 0x100;
                const data = try std.testing.allocator.alloc(u8, try stream.getEndPos());
                defer std.testing.allocator.free(data);
                try std.testing.expectEqual(stream.getEndPos(), try stream.read(data));
                const coff = try std.coff.Coff.init(data, false);
                const parsed = Parsed.init(coff);
                const coff_header = coff.getCoffHeader();
                const offset = coff.coff_header_offset + @sizeOf(std.coff.CoffHeader) + coff_header.size_of_optional_header;
                std.debug.print("offset = {X}, {X}\n", .{ offset + @offsetOf(std.coff.SectionHeader, "virtual_address"), offset + @offsetOf(std.coff.SectionHeader, "virtual_size") });
                for (parsed.coff.getSectionHeaders()) |sechdr| {
                    std.debug.print("{X} - {X}\n", .{ sechdr.virtual_address, sechdr.virtual_address + sechdr.virtual_size });
                }
                var coff_modder: Modder = try Modder.init(std.testing.allocator, &parsed, &stream);
                defer coff_modder.deinit(std.testing.allocator);
                for (coff_modder.addr_sort[0..coff_modder.sechdrs.len]) |idx| {
                    std.debug.print("{X} - {X}\n", .{ coff_modder.sechdrs[idx].virtual_address, coff_modder.sechdrs[idx].virtual_address + coff_modder.sechdrs[idx].virtual_size });
                }
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
                try std.testing.expect(no_cave_result.term == .Exited);
                try std.testing.expectEqual(cave_result.term.Exited, no_cave_result.term.Exited);
                try std.testing.expectEqualStrings(cave_result.stdout, no_cave_result.stdout);
                try std.testing.expectEqualStrings(cave_result.stderr, no_cave_result.stderr);
            }
        }
    }
    if (builtin.os.tag != .windows) {
        return error.SkipZigTest;
    }
}
