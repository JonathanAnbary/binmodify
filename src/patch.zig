//! Provides a generic structure for creating inline hooks in executable files.

const std = @import("std");
const builtin = @import("builtin");

const arch = @import("arch.zig");
const ctl_asm = @import("ctl_asm.zig");

pub const PatchInfo: type = extern struct {
    cave_addr: u64,
    cave_size: u64,
};

pub const Error = error{
    NoFreeSpace,
    UnexpectedEof,
    PatchTooLarge,
};

/// Provides pure_patch() which allows for inserting inline hooks in the given executable.
/// Disasm needs to expose min_insn_size(self: *Self, size: u64, code: []const u8, addr: u64) u64, which returns size rounded up to the nearest instruction.
/// Modder needs to expose addr_to_off(addr: u64), get_cave_option(size: u64, file_range_flags: FileRangeFlags), create_cave(cave_size: u64, cave_option: ret<get_cave_option>, stream: anytype), cave_to_off(cave_option: ret<get_cave_option>, cave_size: u64), off_to_addr(off:u64).
pub fn Patcher(Modder: type, Disasm: type) type {
    return struct {
        modder: Modder,
        arch: arch.Arch,
        mode: arch.Mode,
        endian: arch.Endian,
        disasm: Disasm,

        const Self = @This();
        /// assumes that `parsed` contains information that is true for `reader`.
        /// `parsed` must provde `get_arch()`, `get_mode()`, `get_endian()` and be compatible with the `Modder` init function.
        pub fn init(
            gpa: std.mem.Allocator,
            reader: anytype,
            parsed: anytype,
        ) !Self {
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
                .arch = farch,
                .mode = fmode,
                .endian = fendian,
                .disasm = disasm,
            };
        }

        pub fn deinit(self: *Self, gpa: std.mem.Allocator) void {
            self.modder.deinit(gpa);
            self.disasm.deinit();
        }

        /// insert an inline hook at addresss `addr` which transfers execution to a cave containing the bytes at patch, the bytes that were overridden and then transfers control back to after the hook.
        /// assume that address is the start of an instruction within the `stream`, and that the `stream` contains the same data as the `reader` passed to init.
        /// returns the cave which was created to hold the patch.
        /// example:
        /// before hook:
        ///     <app_inst0><app_inst1><app_inst2><app_inst3>
        /// after hook:
        ///     <app_inst0><branch_inst1><app_inst2><app_inst3>
        ///                 |             L----------┐
        ///                 L <patch><app_inst1><branch_inst1>
        /// The simplest way to think of it is that you are adding the patch bytes to the program in insert mode.
        pub fn pure_patch(self: *Self, addr: u64, patch: []const u8, stream: anytype) !PatchInfo {
            // TODO: think about this 20 (pull out of my ass as the maximum partial instruction size that might be needed).
            var buff: [ctl_asm.MAX_CTL_FLOW + 20]u8 = undefined;
            const off_before_patch = try self.modder.addr_to_off(addr);
            try stream.seekTo(off_before_patch);
            const max = try stream.read(&buff);
            const ctl_transfer_size = @max(
                (try ctl_asm.arch_to_ctl_flow(self.arch, true)).len,
                (try ctl_asm.arch_to_ctl_flow(self.arch, false)).len,
            );
            const insn_to_move_siz = self.disasm.min_insn_size(ctl_transfer_size, buff[0..max], addr);
            std.debug.assert(insn_to_move_siz < buff.len);
            if (patch.len + insn_to_move_siz + ctl_transfer_size > std.math.maxInt(u32)) {
                return Error.PatchTooLarge;
            }
            const cave_size: u32 = @intCast(patch.len + insn_to_move_siz + ctl_transfer_size);
            const cave_option = (try self.modder.get_cave_option(cave_size, .{ .read = true, .execute = true })) orelse return Error.NoFreeSpace;
            try self.modder.create_cave(cave_size, cave_option, stream);

            const off_after_patch = try self.modder.addr_to_off(addr);
            const cave_off = self.modder.cave_to_off(cave_option, cave_size);
            const cave_addr = try self.modder.off_to_addr(cave_off);
            try stream.seekTo(cave_off);
            if (try stream.write(patch) != patch.len) return Error.UnexpectedEof;
            try stream.seekTo(cave_off + patch.len);
            if (try stream.write(buff[0..insn_to_move_siz]) != insn_to_move_siz) return Error.UnexpectedEof;
            const patch_to_cave_size = try ctl_asm.assemble_ctl_transfer(self.arch, self.mode, self.endian, addr, cave_addr, &buff);
            std.debug.assert(patch_to_cave_size == ctl_transfer_size);
            try stream.seekTo(off_after_patch);
            if (try stream.write(buff[0..patch_to_cave_size]) != patch_to_cave_size) return Error.UnexpectedEof;
            const cave_to_patch_size = try ctl_asm.assemble_ctl_transfer(self.arch, self.mode, self.endian, cave_addr + patch.len + insn_to_move_siz, addr + insn_to_move_siz, &buff);
            std.debug.assert(cave_to_patch_size == ctl_transfer_size);
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

const ElfModder = @import("elf/Modder.zig");
const ElfParsed = @import("elf/Parsed.zig");
const CoffModder = @import("coff/Modder.zig");
const CoffParsed = @import("coff/Parsed.zig");

test "elf nop patch no difference" {
    const test_src_path = "./tests/hello_world.zig";
    const test_with_patch_prefix = "./elf_nop_patch_no_difference";
    const native_compile_path = "./elf_nop_hello_world";
    const cwd: std.fs.Dir = std.fs.cwd();
    const optimzes = &.{ "ReleaseSmall", "ReleaseSafe", "ReleaseFast", "Debug" };
    const targets = &.{ "x86_64-linux", "x86-linux", "aarch64-linux", "arm-linux" };
    const qemus = &.{ "qemu-x86_64", "qemu-i386", "qemu-aarch64", "qemu-arm" };
    const nops = &.{ [_]u8{0x90}, [_]u8{0x90}, [_]u8{ 0x1F, 0x20, 0x03, 0xD5 }, [_]u8{ 0xE1, 0xA0, 0x00, 0x00 } };

    {
        const build_native_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-femit-bin=" ++ native_compile_path[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_native_result.stdout);
        defer std.testing.allocator.free(build_native_result.stderr);
        try std.testing.expect(build_native_result.term == .Exited);
    }
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{native_compile_path},
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);
    try std.testing.expect(no_patch_result.term == .Exited);

    inline for (optimzes) |optimize| {
        inline for (targets, qemus, nops) |target, qemu, nop| {
            const test_with_patch_path = test_with_patch_prefix ++ target ++ optimize;

            {
                const build_src_result = try std.process.Child.run(.{
                    .allocator = std.testing.allocator,
                    .argv = &[_][]const u8{ "zig", "build-exe", "-target", target, "-O", optimize, "-ofmt=elf", "-femit-bin=" ++ test_with_patch_path[2..], test_src_path },
                });
                defer std.testing.allocator.free(build_src_result.stdout);
                defer std.testing.allocator.free(build_src_result.stderr);
                try std.testing.expect(build_src_result.term == .Exited);
                try std.testing.expect(build_src_result.stderr.len == 0);
            }

            {
                var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
                defer f.close();
                const patch = nop ** 0x900;
                const parsed = try ElfParsed.init(&f);
                var patcher: Patcher(ElfModder, capstone.Disasm) = try .init(std.testing.allocator, &f, &parsed);
                defer patcher.deinit(std.testing.allocator);
                _ = try patcher.pure_patch(parsed.header.entry, &patch, &f);
            }

            if (builtin.os.tag == .linux) {
                // check output with a cave
                const patch_result = try std.process.Child.run(.{
                    .allocator = std.testing.allocator,
                    .argv = &[_][]const u8{ qemu, test_with_patch_path },
                });
                defer std.testing.allocator.free(patch_result.stdout);
                defer std.testing.allocator.free(patch_result.stderr);
                try std.testing.expect(patch_result.term == .Exited);
                try std.testing.expect(no_patch_result.term == .Exited);
                try std.testing.expectEqual(patch_result.term.Exited, no_patch_result.term.Exited);
                try std.testing.expectEqualStrings(patch_result.stdout, no_patch_result.stdout);
                try std.testing.expectEqualStrings(patch_result.stderr, no_patch_result.stderr);
            }
        }
    }
    if (builtin.os.tag != .linux) {
        return error.SkipZigTest;
    }
}

test "coff nop patch no difference" {
    const test_src_path = "./tests/hello_world.zig";
    const test_with_patch_prefix = "./coff_nop_patch_no_difference";
    const native_compile_path = "./coff_nop_hello_world";
    const cwd: std.fs.Dir = std.fs.cwd();
    const optimzes = &.{ "ReleaseSmall", "ReleaseFast", "Debug" }; // ReleaseSafe seems to be generated without large caves.
    const targets = &.{ "x86_64-windows", "x86-windows" };
    const nops = &.{ [_]u8{0x90}, [_]u8{0x90} };

    {
        const build_native_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-femit-bin=" ++ native_compile_path[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_native_result.stdout);
        defer std.testing.allocator.free(build_native_result.stderr);
        try std.testing.expect(build_native_result.term == .Exited);
    }
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{native_compile_path},
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);
    try std.testing.expect(no_patch_result.term == .Exited);

    inline for (optimzes) |optimize| {
        inline for (targets, nops) |target, nop| {
            const test_with_patch_path = test_with_patch_prefix ++ target ++ optimize ++ ".exe";
            {
                const build_src_result = try std.process.Child.run(.{
                    .allocator = std.testing.allocator,
                    .argv = &[_][]const u8{ "zig", "build-exe", "-target", target, "-O", optimize, "-ofmt=coff", "-femit-bin=" ++ test_with_patch_path[2..], test_src_path },
                });
                defer std.testing.allocator.free(build_src_result.stdout);
                defer std.testing.allocator.free(build_src_result.stderr);
                try std.testing.expect(build_src_result.term == .Exited);
                try std.testing.expect(build_src_result.stderr.len == 0);
            }

            {
                var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
                defer f.close();
                const patch = nop ** 0x200;
                const data = try std.testing.allocator.alloc(u8, try f.getEndPos());
                defer std.testing.allocator.free(data);
                try std.testing.expectEqual(f.getEndPos(), try f.read(data));
                const coff = try std.coff.Coff.init(data, false);
                const parsed = CoffParsed.init(coff);
                var patcher: Patcher(CoffModder, capstone.Disasm) = try .init(std.testing.allocator, &f, &parsed);
                defer patcher.deinit(std.testing.allocator);
                _ = try patcher.pure_patch(parsed.coff.getImageBase() + parsed.coff.getOptionalHeader().address_of_entry_point, &patch, &f);
            }

            if (builtin.os.tag == .windows) {
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
        }
    }
    if (builtin.os.tag != .windows) {
        return error.SkipZigTest;
    }
}

test "elf fizzbuzz fizz always" {
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

    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        try f.seekTo(0xD94);
        const overwrite = [_]u8{0x83}; // changing jz to jae
        try std.testing.expectEqual(overwrite.len, try f.write(&overwrite));
        const patch = [_]u8{ 0xFE, 0xC3 } ** 0x2; // inc bl; inc bl;
        const parsed = try ElfParsed.init(&f);
        var patcher: Patcher(ElfModder, capstone.Disasm) = try .init(std.testing.allocator, &f, &parsed);
        defer patcher.deinit(std.testing.allocator);
        _ = try patcher.pure_patch(0x1001D99, &patch, &f);
    }

    if (builtin.os.tag != .linux) {
        return error.SkipZigTest;
    }
    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(patch_result.term == .Exited);
    try std.testing.expectEqual(0, patch_result.term.Exited);
    try std.testing.expectEqualStrings(expected_output, patch_result.stdout);
    try std.testing.expectEqual(0, patch_result.stderr.len);
}

test "coff fizzbuzz fizz always" {
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

    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        try f.seekTo(0x4DC);
        const overwrite = [_]u8{0x83}; // changing je to jae
        try std.testing.expectEqual(overwrite.len, try f.write(&overwrite));
        try f.seekTo(0);
        const patch = [_]u8{ 0x41, 0xFE, 0xC5 } ** 0x2; // inc r13b; inc r13b;
        const data = try std.testing.allocator.alloc(u8, try f.getEndPos());
        defer std.testing.allocator.free(data);
        try std.testing.expectEqual(f.getEndPos(), try f.read(data));
        const coff = try std.coff.Coff.init(data, false);
        const parsed = CoffParsed.init(coff);
        var patcher: Patcher(CoffModder, capstone.Disasm) = try .init(std.testing.allocator, &f, &parsed);
        defer patcher.deinit(std.testing.allocator);
        _ = try patcher.pure_patch(0x1400010E1, &patch, &f);
    }

    if (builtin.os.tag != .windows) {
        return error.SkipZigTest;
    }
    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(patch_result.term == .Exited);
    try std.testing.expectEqual(0, patch_result.term.Exited);
    try std.testing.expectEqualStrings(expected_output, patch_result.stdout);
    try std.testing.expectEqual(0, patch_result.stderr.len);
}
