const std = @import("std");
const elf = @import("elf.zig");
const arch = @import("arch.zig");
const capstone = @cImport(@cInclude("capstone/capstone.h"));
const ctl_asm = @import("ctl_asm.zig");

const Error = arch.Error;

const FileType = enum {
    Elf,
    PE,
};

pub const PatcherUnmanged = struct {
    to_patch: std.fs.File,
    ftype: FileType,
    farch: arch.Arch,
    file_handler: 
    // mode may be something that changes between patches, not sure about it.
    fmode: arch.Mode,
    fendian: ?arch.Endian,
    patches: std.AutoHashMapUnmanaged(u64, []u8),

    const Self = @This();

    pub fn init(to_patch: std.fs.File, ftype: FileType, farch: arch.Arch, fmode: arch.Mode, fendian: ?arch.Endian) Self {
        return Self{
            .to_patch = to_patch,
            .type = ftype,
            .arch = farch,
            .mode = fmode,
            .endian = fendian,
            .patches = std.AutoHashMapUnmanaged(u64, []u8){},
        };
    }

    // adds a patch to the map of staged patches, patches are not applied, until apply patches is called.
    pub fn add_patch(self: *Self, alloc: std.mem.Allocator, off: u64, patch: []u8) !void {
        try self.patches.put(alloc, off, patch);
    }

    pub fn remove_patch(self: *Self, off: u64) bool {
        return self.patches.remove(off);
    }

    pub fn get_area(self: *Self) void {}
};

pub fn mk_patch(
    file_to_patch: std.fs.File,
    file_type: FileType,
    curr_arch: arch.Arch,
    mode: arch.Mode,
    endian: ?arch.Endian,
) !void {
    if (arch.IS_ENDIANABLE.contains(curr_arch) and endian != null) return Error.ArchNotEndianable;
    var csh: capstone.csh = undefined;
    if (capstone.cs_open(arch.to_cs_arch(curr_arch), arch.to_cs_mode(), &csh) != capstone.CS_ERR_OK) {
        unreachable;
    }
    defer _ = capstone.cs_close(&csh);
    const ctlfh = try ctl_asm.CtlFlowAssembler.init(arch, mode, endian);


    const test_patch = &[_]u8{ 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
    var dst: usize = undefined;
    const c_ident: [*]const u8 = libelf.elf_getident(elf, &dst) orelse {
        std.debug.print("{s}\n", .{libelf.elf_errmsg(libelf.elf_errno())});
        return Error.BeginFailed;
    };
    const ident: []const u8 = c_ident[0..dst];
    const ei_class: EI_CLASS = @enumFromInt(ident[4]);
    var patch_buff: [test_patch.len + 50]u8 = undefined;
    switch (ei_class) {
        .ELFCLASS32 => {
            print_elf(EI_CLASS.ELFCLASS32, elf);
            var temp_data = get_off_data(EI_CLASS.ELFCLASS32, elf, file_offset).?;
            const data_to_patch = BlockInfo{ .block = &temp_data, .addr = off_to_addr(EI_CLASS.ELFCLASS32, elf, file_offset).? };
            const patch_buff_size: libelf.Elf32_Word = @intCast(min_buf_size(csh, temp_data, test_patch.len));
            const data_patch_buff = get_patch_buf(EI_CLASS.ELFCLASS32, elf, patch_buff_size).?;
            data_patch_buff.block.* = patch_buff[0..patch_buff_size];
            try insert_patch(csh, ctlfh, data_to_patch, data_patch_buff, test_patch);

            const temp = libelf.elf_update(elf, libelf.ELF_C_WRITE);
            if (temp == -1) {
                const err = libelf.elf_errno();
                std.debug.print("errno = {}\nerr = {s}\n", .{ err, libelf.elf_errmsg(err) });
            }
            print_elf(EI_CLASS.ELFCLASS32, elf);
            std.debug.print("image size = {}\n", .{temp});
        },
        .ELFCLASS64 => {
            print_elf(EI_CLASS.ELFCLASS64, elf);
            var temp_data = get_off_data(EI_CLASS.ELFCLASS64, elf, file_offset).?;
            const data_to_patch = BlockInfo{ .block = &temp_data, .addr = off_to_addr(EI_CLASS.ELFCLASS64, elf, file_offset).? };
            const patch_buff_size: libelf.Elf64_Word = @intCast(min_buf_size(csh, temp_data, test_patch.len));
            const data_patch_buff = get_patch_buf(EI_CLASS.ELFCLASS64, elf, patch_buff_size).?;
            data_patch_buff.block.* = patch_buff[0..patch_buff_size];
            try insert_patch(csh, ctlfh, data_to_patch, data_patch_buff, test_patch);
            print_elf(EI_CLASS.ELFCLASS64, elf);
            const temp = libelf.elf_update(elf, libelf.ELF_C_WRITE);
            if (temp == -1) {
                const err = libelf.elf_errno();
                std.debug.print("errno = {}\nerr = {s}\n", .{ err, libelf.elf_errmsg(err) });
            }

            std.debug.print("image size = {}\n", .{temp});
        },
    }
}
