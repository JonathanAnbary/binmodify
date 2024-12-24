const std = @import("std");
const arch = @import("arch.zig");

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
pub const CtlFlowAssembler: type = struct {
    arch: arch.Arch,
    mode: arch.Mode,
    endian: ?arch.Endian,

    const Self = @This();

    pub fn init(curr_arch: arch.Arch, mode: arch.Mode, endian: ?arch.Endian) arch.Error!Self {
        // TODO: check that the mode matches the arch, consider if these checks should be performed at all.
        // if (arch.IS_ENDIANABLE.contains(curr_arch) and endian != null) return arch.Error.ArchNotEndianable;
        // try @as(ARCH_MODE_MAP.get(arch), @enumFromInt(mode));
        return .{
            .arch = curr_arch,
            .mode = mode,
            .endian = endian,
        };
    }

    // TODO: change this (no reason to return size since it should be constant)
    pub fn assemble_ctl_transfer(self: *const Self, from: u64, to: u64, buf: []u8) !u8 {
        const ctl_flow_insn = ARCH_TO_CTL_FLOW.get(self.arch).?;
        std.mem.copyForwards(u8, buf[0..ctl_flow_insn.len], ctl_flow_insn);
        const target_op_desc = self.target_operand_bitrange();
        twos_complement(
            self.calc_ctl_tranfer_op(to, from),
            target_op_desc.size,
            self.endian orelse .little,
            buf[target_op_desc.off..][0 .. (target_op_desc.size + 7) / 8],
        );
        return @intCast(ctl_flow_insn.len);
    }

    fn target_operand_bitrange(self: *const Self) OpDesc {
        _ = self.endian;
        return switch (self.arch) {
            .X86 => switch (self.mode) {
                .MODE_64 => OpDesc{ .off = 1, .size = 4 * 8, .signedness = .signed },
                else => unreachable,
            },
            .ARM => switch (self.mode) {
                .ARM => OpDesc{ .off = 0, .size = 3 * 8, .signedness = .signed },
                else => unreachable,
            },
            .AARCH64 => switch (self.mode) {
                .AARCH64 => OpDesc{ .off = 0, .size = 3 * 8, .signedness = .signed },
                else => unreachable,
            },
            .MIPS => switch (self.mode) {
                .MIPS64 => OpDesc{ .off = 0, .size = 26, .signedness = .unsigned },
                else => unreachable,
            },
            else => unreachable,
        };
    }

    fn calc_ctl_tranfer_op(self: *const Self, target: i128, addr: i128) i128 {
        return switch (self.arch) {
            .X86 => switch (self.mode) {
                .MODE_64 => target - (addr + 0x5),
                else => unreachable,
            },
            .ARM => switch (self.mode) {
                .ARM => (target - (addr + 0x8)) >> 0x2,
                else => unreachable,
            },
            .AARCH64 => switch (self.mode) {
                .AARCH64 => (target - addr) >> 0x2,
                else => unreachable,
            },
            .MIPS => switch (self.mode) {
                .MIPS64 => target >> 0x2,
                else => unreachable,
            },
            else => unreachable,
        };
    }

    pub const ARCH_TO_CTL_FLOW = std.EnumMap(arch.Arch, []const u8).init(std.enums.EnumFieldStruct(arch.Arch, ?[]const u8, @as(?[]const u8, null)){
        .ARM = &[_]u8{ 0x00, 0x00, 0x00, 0xea },
        .AARCH64 = &[_]u8{ 0x00, 0x00, 0x00, 0x14 },
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
