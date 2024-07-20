const std = @import("std");
const arch = @import("arch.zig");

const builtin = @import("builtin");

// TODO: check if all architectures use twos complement.
pub fn twos_complement(value: i128, bits: u16, endian: arch.Endian, buffer: []u8) void {
    const bytes = (bits + 7) / 8;
    var temp = blk: {
        if (value < 0) {
            var temp2 = @abs(value);
            temp2 = ~temp2;
            temp2 += 1;
            break :blk temp2;
        } else {
            break :blk @abs(value);
        }
    };
    const save_buf: u8 = if (endian == .big) buffer[0] else buffer[bytes - 1];
    for (0..bytes) |i| {
        buffer[if (endian == .big) bytes - i - 1 else i] = @intCast(temp & 0xff);
        temp >>= 8;
    }
    const one: u8 = 1;
    if (bits % 8 != 0) {
        for (bits % 8..8) |i| {
            buffer[if (endian == .big) 0 else bytes - 1] |= save_buf & one << @intCast(i);
        }
    }
}

test "twos complement" {
    const types = [_]type{ u8, i8, u16, i16, u32, i32, u64, i64 };
    const neg = -123;
    const pos = 123;
    var expected: [100]u8 = undefined;
    var got: [100]u8 = undefined;
    inline for (types) |T| {
        const bits = @typeInfo(T).int.bits;
        const temp_expected = expected[0..@divExact(@typeInfo(T).int.bits, 8)];
        const temp_got = got[0..@divExact(@typeInfo(T).int.bits, 8)];
        std.mem.writeInt(T, temp_expected, std.math.minInt(T), .little);
        twos_complement(std.math.minInt(T), bits, .little, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, std.math.maxInt(T), .little);
        twos_complement(std.math.maxInt(T), bits, .little, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, std.math.minInt(T), .big);
        twos_complement(std.math.minInt(T), bits, .big, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, std.math.maxInt(T), .big);
        twos_complement(std.math.maxInt(T), bits, .big, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        if (@typeInfo(T).int.signedness == .signed) {
            std.mem.writeInt(T, temp_expected, neg, .big);
            twos_complement(neg, bits, .big, temp_got);
            try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
            std.mem.writeInt(T, temp_expected, neg, .little);
            twos_complement(neg, bits, .little, temp_got);
            try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        }
        std.mem.writeInt(T, temp_expected, pos, .big);
        twos_complement(pos, bits, .big, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
        std.mem.writeInt(T, temp_expected, pos, .little);
        twos_complement(pos, bits, .little, temp_got);
        try std.testing.expectEqualSlices(u8, temp_expected, temp_got);
    }
}

pub const CtlFlowAssembler: type = struct {
    arch: arch.Arch,
    mode: arch.Mode,
    endian: arch.Endian,

    const Self = @This();

    pub fn init(curr_arch: arch.Arch, mode: arch.Mode, endian: arch.Endian) arch.Error!Self {
        switch (curr_arch) {
            .X86 => switch (mode) {
                .MODE_64 => {},
                else => return arch.Error.ModeNotSupported,
            },
            else => return arch.Error.ArchNotSupported,
        }
        return .{
            .arch = curr_arch,
            .mode = mode,
            .endian = endian,
        };
    }

    // TODO: change this (no reason to return size since it should be constant)
    pub fn assemble_ctl_transfer(self: *const Self, from: u64, to: u64, buf: []u8) !u8 {
        const ctl_flow_insn = ARCH_TO_CTL_FLOW.get(self.arch) orelse return arch.Error.ArchNotSupported;
        std.mem.copyForwards(u8, buf[0..ctl_flow_insn.len], ctl_flow_insn);
        const target_op_desc = try self.target_operand_bitrange();
        twos_complement(
            try self.calc_ctl_tranfer_op(to, from),
            target_op_desc.size,
            self.endian,
            buf[target_op_desc.off..][0 .. (target_op_desc.size + 7) / 8],
        );
        return @intCast(ctl_flow_insn.len);
    }

    fn target_operand_bitrange(self: *const Self) !OpDesc {
        return switch (self.arch) {
            .X86 => switch (self.mode) {
                .MODE_64 => OpDesc{ .off = 1, .size = 4 * 8, .signedness = .signed },
                else => arch.Error.ModeNotSupported,
            },
            .ARM => switch (self.mode) {
                .ARM => OpDesc{ .off = 0, .size = 3 * 8, .signedness = .signed },
                else => arch.Error.ModeNotSupported,
            },
            .ARM64 => switch (self.mode) {
                .ARM64 => OpDesc{ .off = 0, .size = 3 * 8, .signedness = .signed },
                else => arch.Error.ModeNotSupported,
            },
            .MIPS => switch (self.mode) {
                .MIPS64 => OpDesc{ .off = 0, .size = 26, .signedness = .unsigned },
                else => arch.Error.ModeNotSupported,
            },
            else => arch.Error.ArchNotSupported,
        };
    }

    fn calc_ctl_tranfer_op(self: *const Self, target: i128, addr: i128) !i128 {
        return switch (self.arch) {
            .X86 => switch (self.mode) {
                .MODE_64 => target - (addr + 0x5),
                else => arch.Error.ModeNotSupported,
            },
            .ARM => switch (self.mode) {
                .ARM => (target - (addr + 0x8)) >> 0x2,
                else => arch.Error.ModeNotSupported,
            },
            .ARM64 => switch (self.mode) {
                .ARM64 => (target - addr) >> 0x2,
                else => arch.Error.ModeNotSupported,
            },
            .MIPS => switch (self.mode) {
                .MIPS64 => target >> 0x2,
                else => arch.Error.ModeNotSupported,
            },
            else => arch.Error.ArchNotSupported,
        };
    }

    pub const ARCH_TO_CTL_FLOW = std.EnumMap(arch.Arch, []const u8).init(std.enums.EnumFieldStruct(arch.Arch, ?[]const u8, @as(?[]const u8, null)){
        .ARM = &[_]u8{ 0x00, 0x00, 0x00, 0xea },
        .ARM64 = &[_]u8{ 0x00, 0x00, 0x00, 0x14 },
        .MIPS = &[_]u8{ 0x00, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00 },
        .X86 = &[_]u8{ 0xe9, 0x00, 0x00, 0x00, 0x00 },
        .PPC = &[_]u8{ 0x00, 0x00, 0x00, 0x48 },
        .SPARC = null,
        .SYSZ = null,
        .XCORE = null,
        .EVM = null,
    });

    pub const MAX_CTL_FLOW = blk: {
        var max: u8 = 0;
        for (std.meta.fields(arch.Arch)) |curr_arch| {
            const ctl_flow = ARCH_TO_CTL_FLOW.get(@enumFromInt(curr_arch.value)) orelse continue;
            if (ctl_flow.len > max) max = ctl_flow.len;
        }
        break :blk max;
    };

    const OpDesc: type = struct {
        off: u8,
        size: u8,
        signedness: std.builtin.Signedness,
    };
};

// testing stuff

const keystone = blk: {
    if (builtin.is_test) {
        break :blk @cImport(@cInclude("keystone.h"));
    } else unreachable;
};

fn assemble_ctl_transfer(curr_arch: arch.Arch, mode: arch.Mode, endian: arch.Endian, from: u64, to: u64, buf: []u8) ![]u8 {
    const ctl_flow_engine: CtlFlowAssembler = try CtlFlowAssembler.init(curr_arch, mode, endian);
    const temp = try ctl_flow_engine.assemble_ctl_transfer(from, to, buf);
    return buf[0..temp];
}

test "assemble control flow transfer" {
    const from = 0x400000;
    const to = "0x401000";
    var buf: [100]u8 = undefined;
    const assembled = try ks_assemble(to_ks_arch(arch.Arch.X86), try to_ks_mode(arch.Arch.X86, arch.Mode.MODE_64), "jmp " ++ to, from); // the offset is from the end of the instruction 0x1234567d = 0x12345678 + 0x5.
    defer keystone.ks_free(assembled.ptr);
    try std.testing.expectEqualSlices(
        u8,
        assembled,
        try assemble_ctl_transfer(
            arch.Arch.X86,
            arch.Mode.MODE_64,
            .little,
            from,
            try std.fmt.parseInt(u64, to, 0),
            &buf,
        ),
    );

    // if the instruction starts at addr, you want to get to target.
    // the bytes that will make such jump = (target - (addr + 0x8)) >> 0x2. (there are 3 bytes available for the jmp)
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = (0x401000 - (0x400000 + 0x8)) >> 0x2 = 0x3fe
    // const assembled2 = try assemble(to_ks_arch(arch.Arch.ARM), try to_ks_mode(arch.Arch.ARM, arch.Mode.ARM), "bal #" ++ target, addr); // 0x48d160 = 0x123456 * 4 + 0x8.
    // defer keystone.ks_free(assembled2.ptr);
    // try std.testing.expectEqualSlices(u8, assembled2, try assemble_ctl_transfer(
    //     arch.Arch.ARM,
    //     arch.Mode.ARM,
    //     arch.Endian.little,
    //     try std.fmt.parseInt(u64, target, 0),
    //     addr,
    //     &buf,
    // )); // the 0xea is the bal instruction, it comes at the end for some reason.
    // bytes that will make such jump = (target - addr) >> 0x2. (there are 26 bits available for the jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x400
    // const assembled5 = try assemble(to_ks_arch(arch.Arch.ARM64), try to_ks_mode(arch.Arch.ARM64, arch.Mode.ARM64), "b #" ++ target, addr); // 0x491158 = (0x123456 + 0x1000) << 2.
    // defer keystone.ks_free(assembled5.ptr);
    // try std.testing.expectEqualSlices(u8, assembled5, try assemble_ctl_transfer(
    //     arch.Arch.ARM64,
    //     arch.Mode.ARM64,
    //     arch.Endian.little,
    //     try std.fmt.parseInt(u64, target, 0),
    //     addr,
    //     &buf,
    // ));
    // bytes that will make such jump = target >> 0x2. (there are 26 bits available for the jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 >> 0x2 = 0x100400
    // const assembled3 = try assemble(to_ks_arch(arch.Arch.MIPS), try to_ks_mode(arch.Arch.MIPS, arch.Mode.MIPS64), "j " ++ target, addr); // the jmp target is absolute.
    // defer keystone.ks_free(assembled3.ptr);
    // try std.testing.expectEqualSlices(u8, assembled3, try assemble_ctl_transfer(
    //     arch.Arch.MIPS,
    //     arch.Mode.MIPS64,
    //     arch.Endian.little,
    //     try std.fmt.parseInt(u64, target, 0),
    //     addr,
    //     &buf,
    // ));

    // bytes that will make such jump = target - (addr + 0x5). (there are 4 bytes available for this jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 - (0x400000 + 0x5) = 0xffb
    // bytes that will make such jump = target - addr. (there are 26 bits available for this jmp).
    // for example:
    // addr = 0x400000
    // target = 0x401000
    // jmp bytes = 0x401000 - 0x400000 = 0x1000
    // const assembled4 = try assemble(to_ks_arch(arch.Arch.PPC), try to_ks_mode(arch.Arch.PPC, arch.Mode.PPC64), "b " ++ target, addr); // the jmp target is absolute.
    // defer keystone.ks_free(assembled4.ptr);
    // try std.testing.expectEqualSlices(u8, &[_]u8{ 0x00, 0x10, 0x00, 0x48 }, assembled4);
    //
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
        .SYSZ => keystone.KS_ARCH_SYSTEMZ,
        .XCORE => keystone.KS_ARCH_HEXAGON,
        .EVM => keystone.KS_ARCH_EVM,
    };
}

fn to_ks_mode(comptime curr_arch: arch.Arch, mode: arch.Mode) !keystone.ks_mode {
    return switch (curr_arch) {
        .X86 => switch (mode) {
            .MODE_64 => keystone.KS_MODE_64,
            .MODE_32 => keystone.KS_MODE_32,
            .MODE_16 => keystone.KS_MODE_16,
            else => arch.Error.ArchModeMismatch,
        },
        .ARM => switch (mode) {
            .ARM => keystone.KS_MODE_ARM,
            .THUMB => keystone.KS_MODE_THUMB,
            .ARMV8 => keystone.KS_MODE_ARM + keystone.KS_MODE_V8,
            else => arch.Error.ArchModeMismatch,
        },
        .ARM64 => switch (mode) {
            .ARM64 => keystone.KS_MODE_LITTLE_ENDIAN,
            else => arch.Error.ArchModeMismatch,
        },
        .MIPS => switch (mode) {
            .MIPS32 => keystone.KS_MODE_MIPS32,
            .MIPS64 => keystone.KS_MODE_MIPS64,
            .MICRO => keystone.KS_MODE_MICRO,
            .MIPS3 => keystone.KS_MODE_MIPS3,
            .MIPS32R6 => keystone.KS_MODE_MIPS32R6,
            else => arch.Error.ArchModeMismatch,
        },
        .PPC => switch (mode) {
            .PPC32 => keystone.KS_MODE_PPC32,
            .PPC64 => keystone.KS_MODE_PPC64,
            .QPX => keystone.KS_MODE_QPX,
            else => arch.Error.ArchModeMismatch,
        },
        .SPARC => switch (mode) {
            .SPARC32 => keystone.KS_MODE_SPARC32,
            .SPARC64 => keystone.KS_MODE_SPARC64,
            .V9 => keystone.KS_MODE_V9,
            else => arch.Error.ArchModeMismatch,
        },
        .SYSZ => switch (mode) {
            .big => keystone.KS_MODE_BIG_ENDIAN,
            else => arch.Error.ArchEndianMismatch,
        },
        .XCORE => switch (mode) {
            .little => keystone.KS_MODE_LITTLE_Endian,
            else => arch.Error.ArchEndianMismatch,
        },
        .EVM => switch (mode) {
            .little => keystone.KS_MODE_LITTLE_Endian,
            else => arch.Error.ArchEndianMismatch,
        },
    };
}

fn ks_assemble(curr_arch: keystone.ks_arch, mode: keystone.ks_mode, assembly: []const u8, addr: u64) ![]u8 {
    var temp_ksh: ?*keystone.ks_engine = null;
    const err: keystone.ks_err = keystone.ks_open(curr_arch, @intCast(mode), &temp_ksh);
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
