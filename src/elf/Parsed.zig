const std = @import("std");
const elf = std.elf;

const arch = @import("../arch.zig");

header: elf.Header,

const Self = @This();

pub fn init(stream: anytype) !Self {
    return .{
        .header = try elf.Header.read(stream),
    };
}

pub fn get_arch(self: *const Self) !arch.Arch {
    return switch (self.header.machine) {
        .X86_64 => .X86,
        else => arch.Error.ArchNotSupported,
    };
}

pub fn get_mode(self: *const Self) !arch.Mode {
    return switch (self.header.machine) {
        .X86_64 => if (self.header.is_64) .MODE_64 else .MODE_32,
        else => arch.Error.ArchNotSupported,
    };
}

pub fn get_endian(self: *const Self) !arch.Endian {
    return self.header.endian;
}
