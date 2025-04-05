const std = @import("std");

const builtin = @import("builtin");
const native_endian = builtin.target.cpu.arch.endian();

const shift = @import("../shift.zig");
const FileRangeFlags = @import("../file_range_flags.zig").FileRangeFlags;

const Parsed = @import("Parsed.zig");

fn off_lessThanFn(ranges: *std.MultiArrayList(FileRange), lhs: RangeIndex, rhs: RangeIndex) bool {
    const offs = ranges.items(.off);
    return offs[lhs] < offs[rhs];
}

// TODO: consider if this should have a similar logic, where segments which "contain" other segments come first.
fn addr_lessThanFn(ranges: *std.MultiArrayList(FileRange), lhs: RangeIndex, rhs: RangeIndex) bool {
    const addrs = ranges.items(.addr);
    return addrs[lhs] < addrs[rhs];
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
    sec_idx: RangeIndex,
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

const FileRange: type = struct {
    off: u64,
    filesz: u64,
    addr: u64, // TODO: should be nullable
    memsz: u64,
    flags: FileRangeFlags,
};

const Modder = @This();

const RangeIndex = u16;
const OffIndex = u16;
const AddrIndex = u16;

header: PartialHeader,
ranges: std.MultiArrayList(FileRange), // std.coff.SectionHeader,
off_to_range: [*]RangeIndex,
addr_to_range: [*]RangeIndex,
range_to_off: [*]OffIndex,
range_to_addr: [*]AddrIndex,
adjustments: [*]u64,

pub fn init(gpa: std.mem.Allocator, parsed_source: *const Parsed, parse_source: anytype) Error!Modder {
    _ = parse_source;
    const coff_header = parsed_source.coff.getCoffHeader();
    const optional_header = parsed_source.coff.getOptionalHeader();
    const image_base = parsed_source.coff.getImageBase();
    const size_of_headers = switch (optional_header.magic) {
        std.coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => parsed_source.coff.getOptionalHeader32().size_of_headers,
        std.coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => parsed_source.coff.getOptionalHeader64().size_of_headers,
        else => unreachable, // We assume we have validated the header already
    };
    var ranges = std.MultiArrayList(FileRange){};
    errdefer ranges.deinit(gpa);
    // + 1 for PE header.
    const ranges_count = coff_header.number_of_sections + 1;
    if (ranges_count > std.math.maxInt(RangeIndex)) return Error.TooManyFileRanges;
    try ranges.setCapacity(gpa, ranges_count);
    ranges.appendAssumeCapacity(.{
        .addr = 0,
        .filesz = size_of_headers,
        .memsz = size_of_headers,
        .flags = .{},
        .off = 0,
    });
    for (parsed_source.coff.getSectionHeaders()) |sechdr| {
        ranges.appendAssumeCapacity(.{
            .off = sechdr.pointer_to_raw_data,
            .memsz = sechdr.virtual_size,
            .addr = sechdr.virtual_address,
            .filesz = sechdr.size_of_raw_data,
            .flags = .{
                .execute = sechdr.flags.MEM_EXECUTE == 1,
                .read = sechdr.flags.MEM_READ == 1,
                .write = sechdr.flags.MEM_WRITE == 1,
            },
        });
    }
    const addr_to_range = try gpa.alloc(RangeIndex, ranges_count);
    errdefer gpa.free(addr_to_range);
    const off_to_range = try gpa.alloc(RangeIndex, ranges_count);
    errdefer gpa.free(off_to_range);
    for (0..ranges_count) |i| {
        addr_to_range[i] = @intCast(i);
        off_to_range[i] = @intCast(i);
    }
    std.sort.pdq(RangeIndex, addr_to_range, &ranges, off_lessThanFn);
    std.sort.pdq(RangeIndex, off_to_range, &ranges, addr_lessThanFn);
    const range_to_off = try gpa.alloc(OffIndex, ranges_count);
    errdefer gpa.free(range_to_off);
    const range_to_addr = try gpa.alloc(OffIndex, ranges_count);
    errdefer gpa.free(range_to_addr);
    for (off_to_range, addr_to_range, 0..) |off_idx, addr_idx, idx| {
        range_to_off[off_idx] = @intCast(idx);
        range_to_addr[addr_idx] = @intCast(idx);
    }

    // std.debug.print("\n", .{});
    // for (sechdrs) |*sechdr| {
    //     std.debug.print("{X} - {X} - {X} - {X}\n", .{ sechdr.virtual_address, sechdr.virtual_size, sechdr.pointer_to_raw_data, sechdr.size_of_raw_data });
    // }

    return Modder{
        .header = .{
            .file_alignment = switch (optional_header.magic) {
                std.coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => parsed_source.coff.getOptionalHeader64().file_alignment,
                std.coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => parsed_source.coff.getOptionalHeader32().file_alignment,
                else => unreachable,
            },
            .image_base = image_base,
            .coff_header_offset = parsed_source.coff.coff_header_offset,
            .size_of_optional_header = parsed_source.coff.getCoffHeader().size_of_optional_header,
        },
        .ranges = ranges,
        .addr_to_range = addr_to_range.ptr,
        .range_to_off = range_to_off.ptr,
        .off_to_range = off_to_range.ptr,
        .range_to_addr = range_to_addr.ptr,
        .adjustments = (try gpa.alloc(u64, ranges_count)).ptr,
    };
}

pub fn deinit(self: *Modder, gpa: std.mem.Allocator) void {
    gpa.free(self.adjustments[0..self.ranges.len]);
    gpa.free(self.range_to_addr[0..self.ranges.len]);
    gpa.free(self.range_to_off[0..self.ranges.len]);
    gpa.free(self.off_to_range[0..self.ranges.len]);
    gpa.free(self.addr_to_range[0..self.ranges.len]);
    self.ranges.deinit(gpa);
}

// Get an identifier for the location within the file where additional data could be inserted.
// TODO: consider if this function should also look at existing gaps to help find the cave which requires the minimal shift.
pub fn get_cave_option(self: *const Modder, wanted_size: u64, flags: FileRangeFlags) Error!?SecEdge {
    var i = self.ranges.len;
    const flagss = self.ranges.items(.flags);
    const addrs = self.ranges.items(.addr);
    const memszs = self.ranges.items(.memsz);
    while (i > 0) {
        i -= 1;
        const range_idx = self.off_to_range[i];
        if (flagss[range_idx] != flags) continue;
        // NOTE: this assumes you dont have an upper bound on possible memory address.
        if ((self.range_to_addr[range_idx] == (self.ranges.len - 1)) or
            ((addrs[range_idx] + memszs[range_idx] + wanted_size) < addrs[self.range_to_addr[range_idx] + 1])) return SecEdge{
            .sec_idx = range_idx,
            .is_end = true,
        };
        const prev_sec_mem_bound = (if (self.range_to_addr[range_idx] == 0) 0 else (addrs[self.range_to_addr[range_idx] - 1] + memszs[self.range_to_addr[range_idx] - 1]));
        if (addrs[range_idx] > (wanted_size + prev_sec_mem_bound)) return SecEdge{
            .sec_idx = range_idx,
            .is_end = false,
        };
    }
    return null;
}

fn calc_new_offset(self: *const Modder, index: RangeIndex, size: u64) Error!u64 {
    // TODO: add a check first for the case of an ending edge in which there already exists a large enough gap.
    // and for the case of a start edge whith enough space from the previous segment offset.
    const offs = self.ranges.items(.off);
    const fileszs = self.ranges.items(.filesz);
    const align_offset = (offs[index] + (self.header.file_alignment - (size % self.header.file_alignment))) % self.header.file_alignment;
    const prev_off_end = blk: {
        const off_idx = self.range_to_off[index];
        if (off_idx > 0) {
            const temp = self.off_to_range[off_idx - 1];
            break :blk offs[temp] + fileszs[temp];
        } else break :blk 0;
    };
    if (prev_off_end > fileszs[index]) return Error.IntersectingFileRanges;
    const new_offset = if (offs[index] > (size + prev_off_end))
        (offs[index] - size)
    else
        (prev_off_end + (if ((prev_off_end % self.header.file_alignment) <= align_offset)
            (align_offset)
        else
            (self.header.file_alignment + align_offset)) - (prev_off_end % self.header.file_alignment));
    return new_offset;
}

// NOTE: field changes must NOT change the memory order or offset order!
// TODO: consider what to do when setting the segment which holds the phdrtable itself.
fn set_sechdr_field(self: *Modder, index: RangeIndex, val: u64, comptime field_name: []const u8, parse_source: anytype) Error!void {
    const secidx = index - 1;
    const offset = self.header.coff_header_offset + @sizeOf(std.coff.CoffHeader) + self.header.size_of_optional_header;
    try parse_source.seekTo(offset + @sizeOf(std.coff.SectionHeader) * secidx);
    const T = std.meta.fieldInfo(std.coff.SectionHeader, @field(SectionHeaderFields, field_name)).type;
    const temp: T = @intCast(val);
    try parse_source.seekBy(@offsetOf(std.coff.SectionHeader, field_name));
    const temp2 = std.mem.toBytes(temp);
    if (try parse_source.write(&temp2) != @sizeOf(T)) return Error.UnexpectedEof;
    // @field(self.sechdrs[index], field_name) = @intCast(val);
}

pub fn create_cave(self: *Modder, size: u64, edge: SecEdge, parse_source: anytype) Error!void {
    const offs = self.ranges.items(.off);
    const fileszs = self.ranges.items(.filesz);
    const memszs = self.ranges.items(.memsz);
    const addrs = self.ranges.items(.addr);
    const offset = offs[edge.sec_idx];
    const new_offset: u64 = if (edge.is_end) offset else try self.calc_new_offset(edge.sec_idx, size);
    const first_adjust = if (edge.is_end) size else if (new_offset < offset) size - (offset - new_offset) else size + (new_offset - offset);
    var needed_size = first_adjust;

    var off_idx = self.range_to_off[edge.sec_idx] + 1;
    while (off_idx < self.ranges.len) : (off_idx += 1) {
        const sec_idx = self.off_to_range[off_idx];
        const prev_off_sec_idx = self.off_to_range[off_idx - 1];
        // TODO: should consider calculating the padding and treating it as overwritable.
        const existing_gap = offs[sec_idx] - (offs[prev_off_sec_idx] + fileszs[prev_off_sec_idx]);
        if (needed_size < existing_gap) break;
        needed_size -= existing_gap;
        if ((needed_size % self.header.file_alignment) != 0) needed_size += self.header.file_alignment - (needed_size % self.header.file_alignment);
        self.adjustments[off_idx - (self.range_to_off[edge.sec_idx] + 1)] = needed_size;
    }
    var i = off_idx - (self.range_to_off[edge.sec_idx] + 1);
    while (i > 0) {
        i -= 1;
        const curr_off_idx = i + (self.range_to_off[edge.sec_idx] + 1);
        const sec_idx = self.off_to_range[curr_off_idx];
        try shift.shift_forward(parse_source, offs[sec_idx], offs[sec_idx] + fileszs[sec_idx], self.adjustments[i]);
        offs[sec_idx] += self.adjustments[i];
        try self.set_sechdr_field(sec_idx, offs[sec_idx], "pointer_to_raw_data", parse_source);
    }

    if (!edge.is_end) {
        try shift.shift_forward(parse_source, offs[edge.sec_idx], offs[edge.sec_idx] + fileszs[edge.sec_idx], new_offset + size - offs[edge.sec_idx]);
        addrs[edge.sec_idx] -= self.adjustments[i];
        try self.set_sechdr_field(edge.sec_idx, addrs[edge.sec_idx], "virtual_address", parse_source);
        offs[edge.sec_idx] = new_offset;
        try self.set_sechdr_field(edge.sec_idx, offs[edge.sec_idx], "pointer_to_raw_data", parse_source);
    }
    fileszs[edge.sec_idx] += size;
    try self.set_sechdr_field(edge.sec_idx, fileszs[edge.sec_idx], "size_of_raw_data", parse_source);
    memszs[edge.sec_idx] += size;
    try self.set_sechdr_field(edge.sec_idx, memszs[edge.sec_idx] + size, "virtual_size", parse_source);
    // TODO: might need to adjust some more things.
}

const CompareContext = struct {
    self: *const Modder,
    lhs: u64,
};

fn addr_compareFn(context: CompareContext, rhs: AddrIndex) std.math.Order {
    const addrs = context.self.ranges.items(.addr);
    return std.math.order(context.lhs, addrs[context.self.addr_to_range[rhs]]);
}

pub fn addr_to_off(self: *const Modder, addr: u64) Error!u64 {
    const normalized_addr = if (addr < self.header.image_base) return Error.AddrNotMapped else addr - self.header.image_base;
    const containnig_idx = try self.addr_to_idx(normalized_addr);
    const offs = self.ranges.items(.off);
    const fileszs = self.ranges.items(.filesz);
    const addrs = self.ranges.items(.addr);
    const memszs = self.ranges.items(.memsz);
    if (!(normalized_addr < (addrs[containnig_idx] + memszs[containnig_idx]))) return Error.AddrNotMapped;
    const potenital_off = offs[containnig_idx] + normalized_addr - addrs[containnig_idx];
    if (!(potenital_off < (offs[containnig_idx] + fileszs[containnig_idx]))) return Error.NoMatchingOffset;
    return potenital_off;
}

fn addr_to_idx(self: *const Modder, addr: u64) !RangeIndex {
    // const temp = std.sort.lowerBound(usize, self.addr_to_range[0..self.sechdrs.len], CompareContext{ .self = self, .lhs = addr + 1 }, addr_compareFn);
    // std.debug.print("\nself.sechdrs[self.addr_to_range[temp]].virtual_address = {X}\n", .{self.sechdrs[self.addr_to_range[temp]].virtual_address});
    // std.debug.print("addr = {X}\n", .{addr});
    const lower_bound = std.sort.lowerBound(RangeIndex, self.addr_to_range[0..self.ranges.len], CompareContext{ .self = self, .lhs = addr + 1 }, addr_compareFn);
    if (lower_bound == 0) return Error.AddrNotMapped;
    return self.addr_to_range[lower_bound - 1];
}

fn off_compareFn(context: CompareContext, rhs: OffIndex) std.math.Order {
    const offs = context.self.ranges.items(.off);
    return std.math.order(context.lhs, offs[context.self.off_to_range[rhs]]);
}

pub fn off_to_addr(self: *const Modder, off: u64) Error!u64 {
    const offs = self.ranges.items(.off);
    const fileszs = self.ranges.items(.filesz);
    const addrs = self.ranges.items(.addr);
    const memszs = self.ranges.items(.memsz);
    const containnig_idx = self.off_to_idx(off);
    if (!(off < (offs[containnig_idx] + fileszs[containnig_idx]))) return Error.OffsetNotLoaded;
    if ((memszs[containnig_idx] < fileszs[containnig_idx]) and ((fileszs[containnig_idx] - memszs[containnig_idx]) >= self.header.file_alignment)) return Error.VirtualSizeLessThenFileSize;
    return self.header.image_base + addrs[containnig_idx] + off - offs[containnig_idx];
}

fn off_to_idx(self: *const Modder, off: u64) RangeIndex {
    return self.off_to_range[std.sort.lowerBound(RangeIndex, self.off_to_range[0..self.ranges.len], CompareContext{ .self = self, .lhs = off + 1 }, off_compareFn) - 1];
}

pub fn cave_to_off(self: *const Modder, cave: SecEdge, size: u64) u64 {
    const offs = self.ranges.items(.off);
    const fileszs = self.ranges.items(.filesz);
    return offs[cave.sec_idx] + if (cave.is_end) fileszs[cave.sec_idx] - size else 0;
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

    inline for (optimzes) |optimize| {
        inline for (targets) |target| {
            const test_with_cave_filename = test_with_cave_prefix ++ target ++ optimize ++ ".exe";
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
                var coff_modder: Modder = try Modder.init(std.testing.allocator, &parsed, &stream);
                defer coff_modder.deinit(std.testing.allocator);
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
