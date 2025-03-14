const std = @import("std");
const builtin = @import("builtin");

const arch = @import("arch.zig");
const ElfModder = @import("elf/Modder.zig");
const ElfParsed = @import("elf/Parsed.zig");
const CoffModder = @import("coff/Modder.zig");
const CoffParsed = @import("coff/Parsed.zig");
const common = @import("common.zig");
const ctl_asm = @import("ctl_asm.zig");

pub const PatchInfo: type = extern struct {
    cave_addr: u64,
    cave_size: u64,
};

pub fn Patcher(Modder: type, Disasm: type) type {
    return struct {
        modder: Modder,
        ctl_assembler: ctl_asm.CtlFlowAssembler,
        disasm: Disasm,

        const Self = @This();
        pub const Error = Modder.Error || Disasm.Error || arch.Error;

        pub fn init(
            gpa: std.mem.Allocator,
            reader: anytype,
            parsed: anytype,
        ) Error!Self {
            var modder: Modder = try Modder.init(gpa, parsed, reader);
            errdefer modder.deinit(gpa);
            const farch = try parsed.get_arch();
            // NOTE: mode might be something that is not constant across the file.
            const fmode = try parsed.get_mode();
            const fendian = try parsed.get_endian();
            var disasm: Disasm = try Disasm.init(farch, fmode, fendian);
            errdefer disasm.deinit();

            return Self{
                .modder = modder,
                .ctl_assembler = try ctl_asm.CtlFlowAssembler.init(farch, fmode, fendian),
                .disasm = disasm,
            };
        }

        pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            self.modder.deinit(gpa);
            self.disasm.deinit();
        }

        pub fn pure_patch(self: *Self, addr: u64, patch: []const u8, stream: anytype) !PatchInfo {
            // TODO: think about this 20 (pull out of my ass as the maximum partial instruction size that might be needed).
            var buff: [ctl_asm.CtlFlowAssembler.MAX_CTL_FLOW + 20]u8 = undefined;
            const off_before_patch = try self.modder.addr_to_off(addr);
            try stream.seekTo(off_before_patch);
            const max = try stream.read(&buff);
            const ctl_trasnfer_size = (ctl_asm.CtlFlowAssembler.ARCH_TO_CTL_FLOW.get(self.ctl_assembler.arch) orelse return Error.ArchNotSupported).len;
            const insn_to_move_siz = self.disasm.min_insn_size(ctl_trasnfer_size, buff[0..max], addr);
            std.debug.assert(insn_to_move_siz < buff.len);
            const cave_size = patch.len + insn_to_move_siz + ctl_trasnfer_size;
            const cave_option = (try self.modder.get_cave_option(cave_size, common.FileRangeFlags{ .read = true, .execute = true })) orelse return Error.NoFreeSpace;
            // std.debug.print("\ncave_option = {}\n", .{cave_option});
            try self.modder.create_cave(cave_size, cave_option, stream);
            // if (T == CoffModder) {
            //     for (self.modder.sechdrs) |*sechdr| {
            //         std.debug.print("{X} - {X} - {X} - {X}\n", .{ sechdr.virtual_address, sechdr.virtual_size, sechdr.pointer_to_raw_data, sechdr.size_of_raw_data });
            //     }
            // }

            const off_after_patch = try self.modder.addr_to_off(addr);
            // TODO: mismatch between filesz and memsz is gonna screw me over.
            const cave_off = self.modder.cave_to_off(cave_option, cave_size);
            const cave_addr = try self.modder.off_to_addr(cave_off);
            try stream.seekTo(cave_off);
            if (try stream.write(patch) != patch.len) return Error.UnexpectedEof;
            try stream.seekTo(cave_off + patch.len);
            if (try stream.write(buff[0..insn_to_move_siz]) != insn_to_move_siz) return Error.UnexpectedEof;
            const patch_to_cave_size = try self.ctl_assembler.assemble_ctl_transfer(addr, cave_addr, &buff);
            std.debug.assert(patch_to_cave_size == ctl_trasnfer_size);
            try stream.seekTo(off_after_patch);
            if (try stream.write(buff[0..patch_to_cave_size]) != patch_to_cave_size) return Error.UnexpectedEof;
            const cave_to_patch_size = try self.ctl_assembler.assemble_ctl_transfer(cave_addr + patch.len + insn_to_move_siz, addr + insn_to_move_siz, &buff);
            std.debug.assert(cave_to_patch_size == ctl_trasnfer_size);
            try stream.seekTo(cave_off + patch.len + insn_to_move_siz);
            if (try stream.write(buff[0..cave_to_patch_size]) != cave_to_patch_size) return Error.UnexpectedEof;
            return .{ .cave_addr = cave_addr, .cave_size = cave_size };
        }
    };
}

// testing stuff

const capstone = blk: {
    if (builtin.is_test) {
        break :blk @import("capstone.zig");
    } else unreachable;
};

test "elf nop patch no difference" {
    if (builtin.os.tag != .linux) {
        return error.SkipZigTest;
    }
    const test_src_path = "./tests/hello_world.zig";
    const test_with_patch_path = "./elf_nop_patch_no_difference";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-O", "ReleaseSmall", "-ofmt=elf", "-femit-bin=" ++ test_with_patch_path[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    // check regular output.
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);

    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        const patch = [_]u8{0x90} ** 0x900; // not doing 1000 since the cave size is only 1000 and we need some extra for the overwritten instructions and such.
        const parsed = try ElfParsed.init(&stream);
        var patcher: Patcher(ElfModder, capstone.Disasm) = try .init(std.testing.allocator, &stream, &parsed);
        defer patcher.deinit(std.testing.allocator);
        _ = try patcher.pure_patch(0x1001B34, &patch, &stream);
    }

    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(patch_result.term == .Exited);
    try std.testing.expect(no_patch_result.term == .Exited);
    try std.testing.expectEqual(patch_result.term.Exited, no_patch_result.term.Exited);
    try std.testing.expectEqualStrings(patch_result.stdout, no_patch_result.stdout);
    try std.testing.expectEqualStrings(patch_result.stderr, no_patch_result.stderr);
}

test "coff nop patch no difference" {
    if (builtin.os.tag != .windows) {
        return error.SkipZigTest;
    }
    const test_src_path = "./tests/hello_world.zig";
    const test_with_patch_path = "./coff_nop_patch_no_difference.exe";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-O", "ReleaseSmall", "-target", "x86_64-windows", "-ofmt=coff", "-femit-bin=" ++ test_with_patch_path[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    // check regular output.
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{ "wine", test_with_patch_path },
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);

    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        const patch = [_]u8{0x90} ** 0x90;
        const data = try std.testing.allocator.alloc(u8, try stream.getEndPos());
        defer std.testing.allocator.free(data);
        try std.testing.expectEqual(stream.getEndPos(), try stream.read(data));
        const coff = try std.coff.Coff.init(data, false);
        const parsed = CoffParsed.init(coff);
        var patcher: Patcher(CoffModder, capstone.Disasm) = try .init(std.testing.allocator, &stream, &parsed);
        defer patcher.deinit(std.testing.allocator);
        try patcher.pure_patch(0x1400011BB, &patch, &stream);
    }

    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{ "wine", test_with_patch_path },
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(patch_result.term == .Exited);
    try std.testing.expect(no_patch_result.term == .Exited);
    try std.testing.expectEqual(patch_result.term.Exited, no_patch_result.term.Exited);
    try std.testing.expectEqualStrings(patch_result.stdout, no_patch_result.stdout);
    try std.testing.expectEqualStrings(patch_result.stderr, no_patch_result.stderr);
}

test "elf fizzbuzz fizz always" {
    if (builtin.os.tag != .linux) {
        return error.SkipZigTest;
    }
    const test_src_path = "./tests/fizzbuzz.zig";
    const test_with_patch_path = "./elf_fizzbuzz_fizz_always";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-O", "ReleaseSmall", "-ofmt=elf", "-femit-bin=" ++ test_with_patch_path[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    const expected_output =
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\
    ;

    // check regular output.
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);

    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        try stream.seekTo(0xD94);
        const overwrite = [_]u8{0x83}; // changing jz to jae
        try std.testing.expectEqual(overwrite.len, try stream.write(&overwrite));
        const patch = [_]u8{ 0xFE, 0xC3 } ** 0x2; // inc bl; inc bl;
        const parsed = try ElfParsed.init(&stream);
        var patcher: Patcher(ElfModder, capstone.Disasm) = try .init(std.testing.allocator, &stream, &parsed);
        defer patcher.deinit(std.testing.allocator);
        _ = try patcher.pure_patch(0x1001D99, &patch, &stream);
    }

    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(no_patch_result.term == .Exited);
    try std.testing.expect(patch_result.term == .Exited);
    try std.testing.expectEqual(no_patch_result.term.Exited, patch_result.term.Exited);
    try std.testing.expectEqualStrings(expected_output, patch_result.stdout);
    try std.testing.expectEqualStrings(no_patch_result.stderr, patch_result.stderr);
}

test "coff fizzbuzz fizz always" {
    if (builtin.os.tag != .windows) {
        return error.SkipZigTest;
    }
    const test_src_path = "./tests/fizzbuzz.zig";
    const test_with_patch_path = "./coff_fizzbuzz_fizz_always.exe";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-O", "ReleaseSmall", "-target", "x86_64-windows", "-ofmt=coff", "-femit-bin=" ++ test_with_patch_path[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    const expected_output =
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\
    ;

    // check regular output.
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{ "wine", test_with_patch_path },
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);

    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        try stream.seekTo(0x4E1);
        const overwrite = [_]u8{0x83}; // changing je to jae
        try std.testing.expectEqual(overwrite.len, try stream.write(&overwrite));
        try stream.seekTo(0);
        const patch = [_]u8{ 0x41, 0xFE, 0xC5 } ** 0x2; // inc r13b; inc r13b;
        const data = try std.testing.allocator.alloc(u8, try stream.getEndPos());
        defer std.testing.allocator.free(data);
        try std.testing.expectEqual(stream.getEndPos(), try stream.read(data));
        const coff = try std.coff.Coff.init(data, false);
        const parsed = CoffParsed.init(coff);
        var patcher: Patcher(CoffModder, capstone.Disasm) = try .init(std.testing.allocator, &stream, &parsed);
        defer patcher.deinit(std.testing.allocator);
        try patcher.pure_patch(0x1400010E6, &patch, &stream);
    }

    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{ "wine", test_with_patch_path },
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(no_patch_result.term == .Exited);
    try std.testing.expect(patch_result.term == .Exited);
    try std.testing.expectEqual(no_patch_result.term.Exited, patch_result.term.Exited);
    try std.testing.expectEqualStrings(expected_output, patch_result.stdout);
    try std.testing.expectEqualStrings(no_patch_result.stderr, patch_result.stderr);
}
