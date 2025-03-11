const std = @import("std");

pub const Error: type = error{
    ArchNotEndianable,
    ArchModeMismatch,
    NoFreeSpace,
    ArchNotSupported,
    ModeNotSupported,
    ArchEndianMismatch,
};

pub const Arch: type = enum(u8) {
    ARM,
    ARM64,
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
    // ARM64
    ARM64,
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
