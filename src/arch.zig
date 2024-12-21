const std = @import("std");
const capstone = @cImport(@cInclude("capstone/capstone.h"));

pub const Error: type = error{
    ArchNotEndianable,
    ArchModeMismatch,
    NoFreeSpace,
};

pub const Arch: type = enum(u4) {
    ARM,
    AArch64,
    MIPS,
    X86,
    PPC,
    SPARC,
    SYSTEMZ,
    HEXAGON,
    EVM,
};

pub const Mode: type = enum(u8) {
    // ARM
    ARM,
    THUMB,
    ARMV8,
    // AArch64
    AArch64,
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
    // SYSTEMZ
    SYSTEMZ,
    // HEXAGON
    HEXAGON,
    // EVM
    EVM,
};

pub const Endian: type = enum(u1) {
    Little,
    Big,
};

pub const IS_ENDIANABLE = std.EnumSet(Arch).init(std.enums.EnumFieldStruct(Arch, bool, false){
    .ARM = true,
    .AArch64 = true,
    .MIPS = true,
    .X86 = true,
    .PPC = true,
    .SPARC = true,
    .SYSTEMZ = false,
    .HEXAGON = false,
    .EVM = false,
});

pub fn to_cs_arch(curr_arch: Arch) capstone.cs_arch {
    return switch (curr_arch) {
        .X86 => capstone.CS_ARCH_X86,
        .ARM => capstone.CS_ARCH_ARM,
        .ARM64 => capstone.CS_ARCH_ARM64,
        .MIPS => capstone.CS_ARCH_MIPS,
        .PPC => capstone.CS_ARCH_PPC,
        .SPARC => capstone.CS_ARCH_SPARC,
        .SYSTEMZ => capstone.CS_ARCH_SYSTEMZ,
        .HEXAGON => capstone.CS_ARCH_HEXAGON,
        .EVM => capstone.CS_ARCH_EVM,
    };
}

// TODO: figure out why cs_mode is a c_uint while the constants themselves appear to be c_int.
pub fn to_cs_mode(curr_arch: Arch, mode: Mode, endian: ?Endian) !c_int {
    const cs_endian = blk: {
        if (endian == null) break :blk 0;
        if (IS_ENDIANABLE.contains(curr_arch)) return Error.ArchNotEndianable;
        if (endian == Endian.Big) break :blk capstone.CS_MODE_BIG_ENDIAN;
        break :blk capstone.CS_MODE_LITTLE_ENDIAN;
    };
    return switch (curr_arch) {
        .X86 => cs_endian + switch (mode) {
            .MODE_64 => capstone.CS_MODE_64,
            .MODE_32 => capstone.CS_MODE_32,
            .MODE_16 => capstone.CS_MODE_16,
            else => Error.ArchModeMismatch,
        },
        .ARM => cs_endian + switch (mode) {
            .ARM => capstone.CS_MODE_ARM,
            .THUMB => capstone.CS_MODE_THUMB,
            .ARMV8 => capstone.CS_MODE_ARM + capstone.CS_MODE_V8,
            else => Error.ArchModeMismatch,
        },
        .AArch64 => cs_endian + switch (mode) {
            // TODO: this is kind of sus.
            .AArch64 => 0,
            else => Error.ArchModeMismatch,
        },
        .MIPS => cs_endian + switch (mode) {
            .MIPS32 => capstone.CS_MODE_MIPS32,
            .MIPS64 => capstone.CS_MODE_MIPS64,
            .MICRO => capstone.CS_MODE_MICRO,
            .MIPS3 => capstone.CS_MODE_MIPS3,
            .MIPS32R6 => capstone.CS_MODE_MIPS32R6,
            else => Error.ArchModeMismatch,
        },
        .PPC => cs_endian + switch (mode) {
            .PPC32 => capstone.CS_MODE_PPC32,
            .PPC64 => capstone.CS_MODE_PPC64,
            .QPX => capstone.CS_MODE_QPX,
            else => Error.ArchModeMismatch,
        },
        .SPARC => cs_endian + switch (mode) {
            .SPARC32 => capstone.CS_MODE_SPARC32,
            .SPARC64 => capstone.CS_MODE_SPARC64,
            .V9 => capstone.CS_MODE_V9,
            else => Error.ArchModeMismatch,
        },
        .SYSTEMZ => switch (mode) {
            .SYSTEMZ => capstone.CS_MODE_BIG_ENDIAN,
            else => Error.ArchModeMismatch,
        },
        .HEXAGON => switch (mode) {
            .HEXAGON => capstone.CS_MODE_LITTLE_ENDIAN,
            else => Error.ArchModeMismatch,
        },
        .EVM => switch (mode) {
            .EVM => capstone.CS_MODE_LITTLE_ENDIAN,
            else => Error.ArchModeMismatch,
        },
    };
}
