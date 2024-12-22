const std = @import("std");
const modelf = @import("modelf.zig");
const arch = @import("arch.zig");
const capstone = @cImport(@cInclude("capstone/capstone.h"));
const ctl_asm = @import("ctl_asm.zig");

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

fn to_zig_err(err: capstone.cs_err) CSError!void {
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

const Error = modelf.Error || CSError || arch.Error;

fn min_insn_size(handle: capstone.csh, size: u64, code: []const u8) u64 {
    const insn = capstone.cs_malloc(handle);
    defer capstone.cs_free(insn, 1);
    var code_size = code.len;
    var code_ptr = code.ptr;
    var address: u64 = 0;
    while ((capstone.cs_disasm_iter(handle, @ptrCast(&code_ptr), &code_size, &address, insn)) and (address < size)) {}
    return address;
}

pub const FileType = enum {
    Elf,
    PE,
};

pub const Patcher = struct {
    stream: *std.io.StreamSource,
    ftype: FileType,
    farch: arch.Arch,
    modder: modelf.ElfModder,
    ctl_assembler: ctl_asm.CtlFlowAssembler,
    csh: capstone.csh,
    // NOTE: mode may be something that changes between patches, not sure about it.
    fmode: arch.Mode,
    fendian: ?arch.Endian,

    const Self = @This();

    pub fn init(
        gpa: std.mem.Allocator,
        stream: *std.io.StreamSource,
        ftype: FileType,
        farch: arch.Arch,
        fmode: arch.Mode,
        fendian: ?arch.Endian,
    ) Error!Self {
        std.debug.assert(ftype == FileType.Elf);
        if (arch.IS_ENDIANABLE.contains(farch) and fendian != null) return Error.ArchNotEndianable;

        return Self{
            .stream = stream,
            .ftype = ftype,
            .farch = farch,
            .modder = try modelf.ElfModder.init(gpa, stream),
            .ctl_assembler = try ctl_asm.CtlFlowAssembler.init(farch, fmode, fendian),
            .csh = blk: {
                var handle: capstone.csh = undefined;
                try to_zig_err(capstone.cs_open(arch.to_cs_arch(farch), try arch.to_cs_mode(farch, fmode, fendian), @ptrCast(&handle)));
                break :blk handle;
            },
            .fmode = fmode,
            .fendian = fendian,
        };
    }

    pub fn deinit(self: *Self, gpa: std.mem.Allocator) !void {
        self.modder.deinit(gpa);
        try to_zig_err(capstone.cs_close(&self.csh));
    }

    pub fn pure_patch(self: *Self, addr: u64, patch: []const u8) !void {
        const offsets = self.modder.pheaders.items(modelf.Phdr64Fields.p_offset);
        const fileszs = self.modder.pheaders.items(modelf.Phdr64Fields.p_filesz);
        const vaddrs = self.modder.pheaders.items(modelf.Phdr64Fields.p_vaddr);
        const memszs = self.modder.pheaders.items(modelf.Phdr64Fields.p_filesz);
        // TODO: think about this 20 (pull out of my ass as the maximum partial instruction size that might be needed).
        var buff: [ctl_asm.CtlFlowAssembler.MAX_CTL_FLOW + 20]u8 = undefined;
        const off = try self.modder.addr_to_off(addr);
        try self.stream.seekTo(off);
        const max = try self.stream.read(&buff);
        const ctl_trasnfer_size = ctl_asm.CtlFlowAssembler.ARCH_TO_CTL_FLOW.get(self.farch).?.len;
        const idx = self.modder.addr_to_idx(addr);
        std.debug.assert((addr + ctl_trasnfer_size) <= (vaddrs[idx] + memszs[idx]));
        const insn_to_move_siz = min_insn_size(self.csh, ctl_trasnfer_size, buff[0..max]);
        const patch_size = patch.len + insn_to_move_siz + ctl_trasnfer_size;
        std.debug.assert(insn_to_move_siz < buff.len);
        const cave_option = (try self.modder.get_cave_option(patch_size, modelf.PType.PT_LOAD, modelf.PFlags{ .PF_X = true, .PF_R = true })) orelse return Error.NoFreeSpace;
        const seg_idx = self.modder.pheaders_offset_order[self.modder.top_off_segs[cave_option.top_idx]];
        try self.modder.create_cave(patch.len, cave_option);
        // TODO: mismatch between filesz and memsz is gonna screw me over.
        const temp = if (cave_option.is_end) fileszs[seg_idx] - patch.len else 0;
        const cave_off = offsets[seg_idx] + temp;
        const cave_addr = vaddrs[seg_idx] + temp;
        try self.stream.seekTo(cave_off);
        std.debug.assert(try self.stream.write(patch) == patch.len);
        try self.stream.seekTo(cave_off + patch.len);
        std.debug.assert(try self.stream.write(buff[0..insn_to_move_siz]) == insn_to_move_siz);
        const patch_to_cave_size = try self.ctl_assembler.assemble_ctl_transfer(addr, cave_addr, &buff);
        std.debug.assert(patch_to_cave_size == ctl_trasnfer_size);
        try self.stream.seekTo(off);
        std.debug.assert(try self.stream.write(buff[0..patch_to_cave_size]) == patch_to_cave_size);
        const cave_to_patch_size = try self.ctl_assembler.assemble_ctl_transfer(cave_addr + patch.len + insn_to_move_siz, addr + insn_to_move_siz, &buff);
        std.debug.assert(cave_to_patch_size == ctl_trasnfer_size);
        try self.stream.seekTo(off + insn_to_move_siz);
        std.debug.assert(try self.stream.write(buff[0..cave_to_patch_size]) == cave_to_patch_size);
    }
};
