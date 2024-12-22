const std = @import("std");
const modelf = @import("modelf.zig");
const arch = @import("arch.zig");
const capstone = @cImport(@cInclude("capstone/capstone.h"));
const ctl_asm = @import("ctl_asm.zig");

const Error = arch.Error;

const FileType = enum {
    Elf,
    PE,
};

pub const Patcher = struct {
    to_patch: std.fs.File,
    ftype: FileType,
    farch: arch.Arch,
    modder: modelf.ElfModder,
    ctl_assembler: ctl_asm.CtlFlowAssembler,
    // mode may be something that changes between patches, not sure about it.
    fmode: arch.Mode,
    fendian: ?arch.Endian,

    const Self = @This();

    pub fn init(gpa: std.mem.Allocator, to_patch: std.fs.File, ftype: FileType, farch: arch.Arch, fmode: arch.Mode, fendian: ?arch.Endian) Self {
        std.debug.assert(ftype == FileType.Elf);
        return Self{
            .to_patch = to_patch,
            .ftype = ftype,
            .farch = farch,
            .modder = try modelf.ElfModder.init(gpa, std.io.StreamSource{ .file = to_patch }),
            .ctl_assembler = ctl_asm.CtlFlowAssembler.init(farch, fmode, fendian),
            .mode = fmode,
            .endian = fendian,
        };
    }

    pub fn pure_patch(self: *Self, addr: u64, patch: []const u8) !void {
        const offsets = self.modder.pheaders.items(modelf.Phdr64Fields.p_offset);
        const fileszs = self.modder.pheaders.items(modelf.Phdr64Fields.p_filesz);
        const vaddrs = self.modder.pheaders.items(modelf.Phdr64Fields.p_vaddr);
        const cave_option = (try self.modder.get_cave_option(patch.len, modelf.PType.PT_LOAD, modelf.PFlags{ .PF_X = true, .PF_R = true })) orelse return Error.NoFreeSpace;
        const seg_idx = self.modder.pheaders_offset_order[self.modder.top_segs[cave_option.top_idx]];
        try self.modder.create_cave(patch.len, cave_option);
        const cave_off = offsets[seg_idx] + if (cave_option.is_end) fileszs[seg_idx] - patch.len else 0;
        const cave_addr = vaddrs[seg_idx] + cave_off;
        var buf: [ctl_asm.CtlFlowAssembler.MAX_CTL_FLOW]u8 = undefined;
        const ctl_size = self.ctl_assembler.assemble_ctl_transfer(cave_addr, addr, &buf);
        self.to_patch.seekTo()
    }
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
