const builtin = @import("builtin");

const arch = @import("arch.zig");

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
    UNKNOWN_CS_ERR,
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
        else => CSError.UNKNOWN_CS_ERR,
    };
}

pub fn to_cs_arch(curr_arch: arch.Arch) capstone.cs_arch {
    return switch (curr_arch) {
        .X86 => capstone.CS_ARCH_X86,
        .ARM => capstone.CS_ARCH_ARM,
        .ARM64 => capstone.CS_ARCH_ARM64,
        .MIPS => capstone.CS_ARCH_MIPS,
        .PPC => capstone.CS_ARCH_PPC,
        .SPARC => capstone.CS_ARCH_SPARC,
        .SYSZ => capstone.CS_ARCH_SYSZ,
        .XCORE => capstone.CS_ARCH_XCORE,
        .EVM => capstone.CS_ARCH_EVM,
    };
}

pub const Disasm: type = struct {
    csh: capstone.csh,
    const Self = @This();
    pub const Error: type = error{
        ArchModeMismatch,
        ArchNotSupported,
    } || CSError;

    pub fn init(farch: arch.Arch, fmode: arch.Mode, fendian: arch.Endian) Error!Self {
        var self: Self = undefined;
        try from_capstone_err(capstone.cs_open(to_cs_arch(farch), try to_cs_mode(farch, fmode, fendian), @ptrCast(&self.csh)));
        return self;
    }

    pub fn deinit(self: *Self) void {
        // TODO: figure out why it is that capstone can error on close.
        _ = capstone.cs_close(&self.csh);
    }

    pub fn min_insn_size(self: *const Self, size: u64, code: []const u8, addr: u64) u64 {
        _ = addr;
        const insn: *capstone.cs_insn = capstone.cs_malloc(self.csh);
        defer capstone.cs_free(insn, 1);
        var code_size = code.len;
        var code_ptr = code.ptr;
        var address: u64 = 0;
        while ((capstone.cs_disasm_iter(self.csh, @ptrCast(&code_ptr), &code_size, &address, insn)) and (address < size)) {}
        return address;
    }

    // TODO: figure out why cs_mode is a c_uint while the constants themselves appear to be c_int.
    fn to_cs_mode(curr_arch: arch.Arch, mode: arch.Mode, endian: ?arch.Endian) !capstone.cs_mode {
        const cs_endian = blk: {
            if (endian == null) break :blk 0;
            if (endian == arch.Endian.big) break :blk capstone.CS_MODE_BIG_ENDIAN;
            break :blk capstone.CS_MODE_LITTLE_ENDIAN;
        };
        return switch (curr_arch) {
            .X86 => cs_endian + @as(c_uint, @intCast(switch (mode) {
                .MODE_64 => capstone.CS_MODE_64,
                .MODE_32 => capstone.CS_MODE_32,
                .MODE_16 => capstone.CS_MODE_16,
                else => return Error.ArchModeMismatch,
            })),
            .ARM => cs_endian + @as(c_uint, @intCast(switch (mode) {
                .ARM => capstone.CS_MODE_ARM,
                .THUMB => capstone.CS_MODE_THUMB,
                .ARMV8 => capstone.CS_MODE_ARM + capstone.CS_MODE_V8,
                else => return Error.ArchModeMismatch,
            })),
            .ARM64 => cs_endian + @as(c_uint, @intCast(switch (mode) {
                // TODO: this is kind of sus.
                .ARM64 => 0,
                else => return Error.ArchModeMismatch,
            })),
            .MIPS => cs_endian + @as(c_uint, @intCast(switch (mode) {
                .MIPS32 => capstone.CS_MODE_MIPS32,
                .MIPS64 => capstone.CS_MODE_MIPS64,
                .MICRO => capstone.CS_MODE_MICRO,
                .MIPS3 => capstone.CS_MODE_MIPS3,
                .MIPS32R6 => capstone.CS_MODE_MIPS32R6,
                else => return Error.ArchModeMismatch,
            })),
            // .PPC => cs_endian + @as(c_uint, @intCast(switch (mode) {
            //     .PPC32 => capstone.CS_MODE_PPC32,
            //     .PPC64 => capstone.CS_MODE_PPC64,
            //     .QPX => capstone.CS_MODE_QPX,
            //     else => return Error.ArchModeMismatch,
            // })),
            // .SPARC => cs_endian + @as(c_uint, @intCast(switch (mode) {
            //     .SPARC32 => capstone.CS_MODE_SPARC32,
            //     .SPARC64 => capstone.CS_MODE_SPARC64,
            //     .V9 => capstone.CS_MODE_V9,
            //     else => return Error.ArchModeMismatch,
            // })),
            .SYSZ => @as(c_uint, @intCast(switch (mode) {
                .SYSZ => capstone.CS_MODE_BIG_ENDIAN,
                else => return Error.ArchModeMismatch,
            })),
            .XCORE => @as(c_uint, @intCast(switch (mode) {
                .XCORE => capstone.CS_MODE_LITTLE_ENDIAN,
                else => return Error.ArchModeMismatch,
            })),
            .EVM => @as(c_uint, @intCast(switch (mode) {
                .EVM => capstone.CS_MODE_LITTLE_ENDIAN,
                else => return Error.ArchModeMismatch,
            })),
            else => return Error.ArchNotSupported,
        };
    }
};
