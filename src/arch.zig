const std = @import("std");
const capstone = @cImport(@cInclude("capstone/capstone.h"));

pub const Error: type = error{
    ArchNotEndianable,
    ArchModeMismatch,
    NoFreeSpace,
    ArchNotSupported,
    ArchEndianMismatch,
};

pub const Arch: type = enum(u4) {
    ARM,
    AARCH64,
    MIPS,
    X86,
    PPC,
    SPARC,
    SYSZ,
    XCORE,
    EVM,
};

pub const Mode: type = enum(u8) {
    // ARM
    ARM,
    THUMB,
    ARMV8,
    // AARCH64
    AARCH64,
    // MIPS
    MIPS32,
    MIPS64,
    MICRO,
    MIPS3,
    MIPS32R6,
    // X86
    MODE_16,
    MODE_32,
    MODE_64,
    // PPC
    PPC32,
    PPC64,
    QPX,
    // SPARC
    SPARC32,
    SPARC64,
    V9,
    // SYSZ
    SYSZ,
    // XCORE
    XCORE,
    // EVM
    EVM,
};

pub const Endian: type = std.builtin.Endian;

pub const IS_ENDIANABLE = std.EnumSet(Arch).init(std.enums.EnumFieldStruct(Arch, bool, false){
    .ARM = true,
    .AARCH64 = true,
    .MIPS = true,
    .X86 = true,
    .PPC = true,
    .SPARC = true,
    .SYSZ = false,
    .XCORE = false,
    .EVM = false,
});

pub fn to_cs_arch(curr_arch: Arch) capstone.cs_arch {
    return switch (curr_arch) {
        .X86 => capstone.CS_ARCH_X86,
        .ARM => capstone.CS_ARCH_ARM,
        .AARCH64 => capstone.CS_ARCH_ARM64,
        .MIPS => capstone.CS_ARCH_MIPS,
        .PPC => capstone.CS_ARCH_PPC,
        .SPARC => capstone.CS_ARCH_SPARC,
        .SYSZ => capstone.CS_ARCH_SYSZ,
        .XCORE => capstone.CS_ARCH_XCORE,
        .EVM => capstone.CS_ARCH_EVM,
    };
}

// TODO: figure out why cs_mode is a c_uint while the constants themselves appear to be c_int.
pub fn to_cs_mode(curr_arch: Arch, mode: Mode, endian: ?Endian) !capstone.cs_mode {
    const cs_endian = blk: {
        if (endian == null) break :blk 0;
        if (IS_ENDIANABLE.contains(curr_arch)) return Error.ArchNotEndianable;
        if (endian == Endian.big) break :blk capstone.CS_MODE_BIG_ENDIAN;
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
        .AARCH64 => cs_endian + @as(c_uint, @intCast(switch (mode) {
            // TODO: this is kind of sus.
            .AARCH64 => 0,
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
