const std = @import("std");

const arch = @import("arch.zig");
const utils = @import("utils.zig");
const modelf = @import("modelf.zig");
const modcoff = @import("modcoff.zig");
const ctl_asm = @import("ctl_asm.zig");

const capstone = @cImport(@cInclude("capstone/capstone.h"));

const CSError = error{
    CS_ERR_MEM,
    CS_ERR_ARCH,
    CS_ERR_HANDLE,
    CS_ERR_CSH,
    CS_ERR_MODE,
    CS_ERR_OPTION,
    CS_ERR_DETAIL,
    CS_ERR_MEMSETUP,
    CS_ERR_VERSION,
    CS_ERR_DIET,
    CS_ERR_SKIPDATA,
    CS_ERR_X86_ATT,
    CS_ERR_X86_INTEL,
    CS_ERR_X86_MASM,
    UNKNOWN,
};

fn from_capstone_err(err: capstone.cs_err) CSError!void {
    return switch (err) {
        capstone.CS_ERR_OK => return,
        capstone.CS_ERR_MEM => CSError.CS_ERR_MEM,
        capstone.CS_ERR_ARCH => CSError.CS_ERR_ARCH,
        capstone.CS_ERR_HANDLE => CSError.CS_ERR_HANDLE,
        capstone.CS_ERR_CSH => CSError.CS_ERR_CSH,
        capstone.CS_ERR_MODE => CSError.CS_ERR_MODE,
        capstone.CS_ERR_OPTION => CSError.CS_ERR_OPTION,
        capstone.CS_ERR_DETAIL => CSError.CS_ERR_DETAIL,
        capstone.CS_ERR_MEMSETUP => CSError.CS_ERR_MEMSETUP,
        capstone.CS_ERR_VERSION => CSError.CS_ERR_VERSION,
        capstone.CS_ERR_DIET => CSError.CS_ERR_DIET,
        capstone.CS_ERR_SKIPDATA => CSError.CS_ERR_SKIPDATA,
        capstone.CS_ERR_X86_ATT => CSError.CS_ERR_X86_ATT,
        capstone.CS_ERR_X86_INTEL => CSError.CS_ERR_X86_INTEL,
        capstone.CS_ERR_X86_MASM => CSError.CS_ERR_X86_MASM,
        else => CSError.UNKNOWN,
    };
}

const Error = modcoff.Error || modelf.Error || CSError || arch.Error;

fn min_insn_size(handle: capstone.csh, size: u64, code: []const u8) u64 {
    const insn = capstone.cs_malloc(handle);
    defer capstone.cs_free(insn, 1);
    var code_size = code.len;
    var code_ptr = code.ptr;
    var address: u64 = 0;
    while ((capstone.cs_disasm_iter(handle, @ptrCast(&code_ptr), &code_size, &address, insn)) and (address < size)) {}
    return address;
}

pub fn Patcher(ModderT: type) type {
    return struct {
        stream: *std.io.StreamSource,
        farch: arch.Arch,
        modder: ModderT,
        ctl_assembler: ctl_asm.CtlFlowAssembler,
        csh: capstone.csh,
        // NOTE: mode may be something that changes between patches, not sure about it.
        fmode: arch.Mode,
        fendian: ?arch.Endian,

        const Self = @This();

        pub fn init(
            gpa: std.mem.Allocator,
            stream: *std.io.StreamSource,
            farch: arch.Arch,
            fmode: arch.Mode,
            fendian: ?arch.Endian,
        ) Error!Self {
            if (arch.IS_ENDIANABLE.contains(farch) and fendian != null) return Error.ArchNotEndianable;
            var modder: ModderT = try ModderT.init(gpa, stream);
            errdefer modder.deinit(gpa);

            return Self{
                .stream = stream,
                .farch = farch,
                .modder = modder,
                .ctl_assembler = try ctl_asm.CtlFlowAssembler.init(farch, fmode, fendian),
                .csh = blk: {
                    var handle: capstone.csh = undefined;
                    try from_capstone_err(capstone.cs_open(arch.to_cs_arch(farch), try arch.to_cs_mode(farch, fmode, fendian), @ptrCast(&handle)));
                    break :blk handle;
                },
                .fmode = fmode,
                .fendian = fendian,
            };
        }

        pub fn deinit(self: *Self, gpa: std.mem.Allocator) !void {
            self.modder.deinit(gpa);
            try from_capstone_err(capstone.cs_close(&self.csh));
        }

        pub fn pure_patch(self: *Self, addr: u64, patch: []const u8) !void {
            // TODO: think about this 20 (pull out of my ass as the maximum partial instruction size that might be needed).
            var buff: [ctl_asm.CtlFlowAssembler.MAX_CTL_FLOW + 20]u8 = undefined;
            const off_before_patch = try self.modder.addr_to_off(addr);
            try self.stream.seekTo(off_before_patch);
            const max = try self.stream.read(&buff);
            const ctl_trasnfer_size = (ctl_asm.CtlFlowAssembler.ARCH_TO_CTL_FLOW.get(self.farch) orelse return Error.ArchNotSupported).len;
            const insn_to_move_siz = min_insn_size(self.csh, ctl_trasnfer_size, buff[0..max]);
            const cave_size = patch.len + insn_to_move_siz + ctl_trasnfer_size;
            std.debug.assert(insn_to_move_siz < buff.len);
            const cave_option = (try self.modder.get_cave_option(cave_size, utils.FileRangeFlags{ .read = true, .execute = true })) orelse return Error.NoFreeSpace;
            try self.modder.create_cave(cave_size, cave_option);
            const off_after_patch = try self.modder.addr_to_off(addr);
            // TODO: mismatch between filesz and memsz is gonna screw me over.
            const cave_off = self.modder.cave_to_off(cave_option, cave_size);
            const cave_addr = try self.modder.off_to_addr(cave_off);
            try self.stream.seekTo(cave_off);
            std.debug.assert(try self.stream.write(patch) == patch.len);
            try self.stream.seekTo(cave_off + patch.len);
            std.debug.assert(try self.stream.write(buff[0..insn_to_move_siz]) == insn_to_move_siz);
            const patch_to_cave_size = try self.ctl_assembler.assemble_ctl_transfer(addr, cave_addr, &buff);
            std.debug.assert(patch_to_cave_size == ctl_trasnfer_size);
            try self.stream.seekTo(off_after_patch);
            std.debug.assert(try self.stream.write(buff[0..patch_to_cave_size]) == patch_to_cave_size);
            const cave_to_patch_size = try self.ctl_assembler.assemble_ctl_transfer(cave_addr + patch.len + insn_to_move_siz, addr + insn_to_move_siz, &buff);
            std.debug.assert(cave_to_patch_size == ctl_trasnfer_size);
            try self.stream.seekTo(cave_off + patch.len + insn_to_move_siz);
            std.debug.assert(try self.stream.write(buff[0..cave_to_patch_size]) == cave_to_patch_size);
        }
    };
}

test "elf nop patch no difference" {
    // NOTE: technically I could build the binary from source but I am unsure of a way to ensure that it will result in the exact same binary each time. (which would make the test flaky, since it might be that there is no viable code cave.).
    const test_path = "./tests/hello_world";
    const test_with_patch_path = "./elf_nop_patch_no_difference";
    const cwd: std.fs.Dir = std.fs.cwd();
    try cwd.copyFile(test_path, cwd, test_with_patch_path, .{});

    // check regular output.
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);

    // create cave.
    // NOTE: need to put this in a block since the file must be closed before the next process can execute.
    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        const patch = [_]u8{0x90} ** 0x900; // not doing 1000 since the cave size is only 1000 and we need some extra for the overwritten instructions and such.
        var patcher: Patcher(modelf.ElfModder) = try Patcher(modelf.ElfModder).init(std.testing.allocator, &stream, arch.Arch.X86, arch.Mode.MODE_64, null);
        defer patcher.deinit(std.testing.allocator) catch |err| std.debug.panic("Patcher deinit failed {}", .{err});
        try patcher.pure_patch(0x1001B3C, &patch);
    }

    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(patch_result.term.Exited == no_patch_result.term.Exited);
    try std.testing.expectEqualStrings(patch_result.stdout, no_patch_result.stdout);
    try std.testing.expectEqualStrings(patch_result.stderr, no_patch_result.stderr);
}

test "coff nop patch no difference" {
    // NOTE: technically I could build the binary from source but I am unsure of a way to ensure that it will result in the exact same binary each time. (which would make the test flaky, since it might be that there is no viable code cave.).
    const test_path = "./tests/hello_world.exe";
    const test_with_patch_path = "./coff_nop_patch_no_difference.exe";
    const cwd: std.fs.Dir = std.fs.cwd();
    try cwd.copyFile(test_path, cwd, test_with_patch_path, .{});

    // check regular output.
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);

    // create cave.
    // NOTE: need to put this in a block since the file must be closed before the next process can execute.
    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        const patch = [_]u8{0x90} ** 0x900; // not doing 1000 since the cave size is only 1000 and we need some extra for the overwritten instructions and such.
        var patcher: Patcher(modcoff.CoffModder) = try Patcher(modcoff.CoffModder).init(std.testing.allocator, &stream, arch.Arch.X86, arch.Mode.MODE_64, null);
        defer patcher.deinit(std.testing.allocator) catch |err| std.debug.panic("Patcher deinit failed {}", .{err});
        try patcher.pure_patch(0x140001F88, &patch);
    }

    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(patch_result.term.Exited == no_patch_result.term.Exited);
    try std.testing.expectEqualStrings(patch_result.stdout, no_patch_result.stdout);
    try std.testing.expectEqualStrings(patch_result.stderr, no_patch_result.stderr);
}
