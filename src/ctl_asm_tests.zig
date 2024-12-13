// The tests for the control flow assembler are in a separate file in order to allow for linking to keystone for testing only.
const std = @import("std");
const arch = @import("arch.zig");
const ctl_asm = @import("ctl_asm.zig");
const keystone = @cImport(@cInclude("keystone.h"));

fn assemble_ctl_transfer(curr_arch: arch.Arch, mode: u64, endian: arch.Endian, target: u64, addr: u64, buf: []u8) []u8 {
    const ctl_flow_engine: ctl_asm.CtlFlowAssembler = ctl_asm.CtlFlowAssembler.init(curr_arch, mode, endian);
    return ctl_flow_engine.assemble_ctl_transfer(target, addr, buf);
}

test "twos complement" {
    const types = [_]type{ u8, i8, u16, i16, u32, i32, u64, i64 };
    const neg = -123;
    const pos = 123;
    var expected: [100]u8 = undefined;
    var got: [100]u8 = undefined;
    inline for (types) |T| {
        const bits = @typeInfo(T).Int.bits;
        const temp_expected = expected[0..@divExact(@typeInfo(T).Int.bits, 8)];
        const temp_got = got[0..@divExact(@typeInfo(T).Int.bits, 8)];
        std.mem.writeInt(T, temp_expected, std.math.minInt(T), .little);
        ctl_asm.twos_complement(std.math.minInt(T), bits, .little, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, std.math.maxInt(T), .little);
        ctl_asm.twos_complement(std.math.maxInt(T), bits, .little, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, std.math.minInt(T), .big);
        ctl_asm.twos_complement(std.math.minInt(T), bits, .big, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, std.math.maxInt(T), .big);
        ctl_asm.twos_complement(std.math.maxInt(T), bits, .big, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        if (@typeInfo(T).Int.signedness == .signed) {
            std.mem.writeInt(T, temp_expected, neg, .big);
            ctl_asm.twos_complement(neg, bits, .big, temp_got);
            try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
            std.mem.writeInt(T, temp_expected, neg, .little);
            ctl_asm.twos_complement(neg, bits, .little, temp_got);
            try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        }
        std.mem.writeInt(T, temp_expected, pos, .big);
        ctl_asm.twos_complement(pos, bits, .big, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, pos, .little);
        ctl_asm.twos_complement(pos, bits, .little, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
    }
}

test "assemble control flow transfer" {
    const addr = 0x400000;
    const target = "0x401000";
    var buf: [100]u8 = undefined;
    // if the instruction starts at addr, you want to get to target.
    // the bytes that will make such jump = (target - (addr + 0x8)) >> 0x2. (there are 3 bytes available for the jmp)
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = (0x401000 - (0x400000 + 0x8)) >> 0x2 = 0x3fe
    const assembled2 = try assemble(to_ks_arch(arch.Arch.ARM), to_ks_mode(arch.Arch.ARM, arch.ARM.ARM), "bal #" ++ target, addr); // 0x48d160 = 0x123456 * 4 + 0x8.
    defer keystone.ks_free(assembled2.ptr);
    try std.testing.expectEqualSlices(u8, assembled2, try assemble_ctl_transfer(
        arch.Arch.ARM,
        @intFromEnum(arch.ARM.ARM),
        arch.Endian.Little,
        try std.fmt.parseInt(u64, target, 0),
        addr,
        &buf,
    )); // the 0xea is the bal instruction, it comes at the end for some reason.
    // bytes that will make such jump = (target - addr) >> 0x2. (there are 26 bits available for the jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x400
    const assembled5 = try assemble(to_ks_arch(arch.Arch.AArch64), to_ks_mode(arch.Arch.AArch64, arch.AArch64.AArch64), "b #" ++ target, addr); // 0x491158 = (0x123456 + 0x1000) << 2.
    defer keystone.ks_free(assembled5.ptr);
    try std.testing.expectEqualSlices(u8, assembled5, try assemble_ctl_transfer(
        arch.Arch.AArch64,
        @intFromEnum(arch.AArch64.AArch64),
        arch.Endian.Little,
        try std.fmt.parseInt(u64, target, 0),
        addr,
        &buf,
    ));
    // bytes that will make such jump = target >> 0x2. (there are 26 bits available for the jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 >> 0x2 = 0x100400
    const assembled3 = try assemble(to_ks_arch(arch.Arch.MIPS), to_ks_mode(arch.Arch.MIPS, arch.MIPS.MIPS64), "j " ++ target, addr); // the jmp target is absolute.
    defer keystone.ks_free(assembled3.ptr);
    try std.testing.expectEqualSlices(u8, assembled3, try assemble_ctl_transfer(
        arch.Arch.MIPS,
        @intFromEnum(arch.MIPS.MIPS64),
        arch.Endian.Little,
        try std.fmt.parseInt(u64, target, 0),
        addr,
        &buf,
    ));

    // bytes that will make such jump = target - (addr + 0x5). (there are 4 bytes available for this jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 - (0x400000 + 0x5) = 0xffb
    const assembled = try assemble(to_ks_arch(arch.Arch.X86), to_ks_mode(arch.Arch.X86, arch.MODE.MODE_64), "jmp " ++ target, addr); // the offset is from the end of the instruction 0x1234567d = 0x12345678 + 0x5.
    defer keystone.ks_free(assembled.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xe9, 0xfb, 0x0f, 0x00, 0x00 }, assembled);
    // bytes that will make such jump = target - addr. (there are 26 bits available for this jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 - 0x400000 = 0x1000
    const assembled4 = try assemble(to_ks_arch(arch.Arch.PPC), to_ks_mode(arch.Arch.PPC, arch.PPC.PPC64), "b " ++ target, addr); // the jmp target is absolute.
    defer keystone.ks_free(assembled4.ptr);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x10, 0x00, 0x48 }, assembled4);

    //const assembled6 = try assemble(to_ks_arch(ARCH.SPARC), to_ks_mode(ARCH.SPARC, SPARC.SPARC32), "b " ++ target, addr); // the jmp target is absolute.
    //defer keystone.ks_free(assembled6.ptr);
    //try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x10, 0x00, 0x48 }, assembled6);
}

fn to_ks_arch(curr_arch: arch.Arch) keystone.ks_arch {
    return switch (curr_arch) {
        .X86 => keystone.KS_ARCH_X86,
        .ARM => keystone.KS_ARCH_ARM,
        .ARM64 => keystone.KS_ARCH_ARM64,
        .MIPS => keystone.KS_ARCH_MIPS,
        .PPC => keystone.KS_ARCH_PPC,
        .SPARC => keystone.KS_ARCH_SPARC,
        .SYSTEMZ => keystone.KS_ARCH_SYSTEMZ,
        .HEXAGON => keystone.KS_ARCH_HEXAGON,
        .EVM => keystone.KS_ARCH_EVM,
    };
}

fn to_ks_mode(comptime curr_arch: arch.Arch, mode: arch.ARCH_MODE_MAP.get(curr_arch).?) c_int {
    return switch (curr_arch) {
        .X86 => switch (mode) {
            .MODE_64 => keystone.KS_MODE_64,
            .MODE_32 => keystone.KS_MODE_32,
            .MODE_16 => keystone.KS_MODE_16,
        },
        .ARM => switch (mode) {
            .ARM => keystone.KS_MODE_ARM,
            .THUMB => keystone.KS_MODE_THUMB,
            .ARMV8 => keystone.KS_MODE_ARM + keystone.KS_MODE_V8,
        },
        .ARM64 => switch (mode) {
            .ARM64 => keystone.KS_MODE_LITTLE_ENDIAN,
        },
        .MIPS => switch (mode) {
            .MIPS32 => keystone.KS_MODE_MIPS32,
            .MIPS64 => keystone.KS_MODE_MIPS64,
            .MICRO => keystone.KS_MODE_MICRO,
            .MIPS3 => keystone.KS_MODE_MIPS3,
            .MIPS32R6 => keystone.KS_MODE_MIPS32R6,
        },
        .PPC => switch (mode) {
            .PPC32 => keystone.KS_MODE_PPC32,
            .PPC64 => keystone.KS_MODE_PPC64,
            .QPX => keystone.KS_MODE_QPX,
        },
        .SPARC => switch (mode) {
            .SPARC32 => keystone.KS_MODE_SPARC32,
            .SPARC64 => keystone.KS_MODE_SPARC64,
            .V9 => keystone.KS_MODE_V9,
        },
        .SYSTEMZ => switch (mode) {
            .big => keystone.KS_MODE_BIG_ENDIAN,
        },
        .HEXAGON => switch (mode) {
            .little => keystone.KS_MODE_LITTLE_Endian,
        },
        .EVM => switch (mode) {
            .little => keystone.KS_MODE_LITTLE_Endian,
        },
    };
}

fn assemble(curr_arch: keystone.ks_arch, mode: c_int, assembly: []const u8, addr: u64) ![]u8 {
    var temp_ksh: ?*keystone.ks_engine = null;
    const err: keystone.ks_err = keystone.ks_open(curr_arch, mode, &temp_ksh);
    if ((err != keystone.KS_ERR_OK) or (temp_ksh == null)) {
        std.debug.print("err = {x}\n", .{err});
        unreachable;
    }
    const ksh: *keystone.ks_engine = temp_ksh.?;
    defer std.debug.assert(keystone.ks_close(ksh) == 0);

    var encode: ?[*]u8 = null;
    var siz: usize = undefined;
    var enc_count: usize = undefined;
    if (keystone.ks_asm(ksh, @as(?[*]const u8, @ptrCast(assembly)), addr, &encode, &siz, &enc_count) != keystone.KS_ERR_OK) {
        std.debug.print("ERROR: ks_asm() failed & count = {}, error = {}\n", .{ enc_count, keystone.ks_errno(ksh) });
        unreachable;
    }
    // the caller is responsible for calling keystone.ks_free.
    // defer keystone.ks_free(encode);
    return encode.?[0..siz];
}
