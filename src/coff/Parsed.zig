const std = @import("std");

const arch = @import("../arch.zig");

coff: std.coff.Coff,

const Self = @This();

pub fn init(coff: std.coff.Coff) Self {
    return .{
        .coff = coff,
    };
}

pub fn get_arch(self: *const Self) !arch.Arch {
    return switch (self.coff.getCoffHeader().machine) {
        .X64 => .X86,
        else => arch.Error.ArchNotSupported,
    };
}

pub fn get_mode(self: *const Self) !arch.Mode {
    return switch (self.coff.getCoffHeader().machine) {
        .X64 => switch (self.coff.getOptionalHeader().magic) {
            std.coff.IMAGE_NT_OPTIONAL_HDR32_MAGIC => .MODE_32,
            std.coff.IMAGE_NT_OPTIONAL_HDR64_MAGIC => .MODE_64,
            else => std.coff.CoffError.InvalidPEMagic,
        },
        else => arch.Error.ArchNotSupported,
    };
}

pub fn get_endian(self: *const Self) !arch.Endian {
    return switch (self.coff.getCoffHeader().machine) {
        .X64 => .little,
        else => arch.Error.ArchNotSupported,
    };
}
