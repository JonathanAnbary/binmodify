const std = @import("std");
const builtin = @import("builtin");

pub const patch = @import("patch.zig");
pub const arch = @import("arch.zig");
pub const ElfModder = @import("elf/Modder.zig");
pub const CoffModder = @import("coff/Modder.zig");
pub const ElfParsed = @import("elf/Parsed.zig");
pub const CoffParsed = @import("coff/Parsed.zig");
pub const FileRangeFlags = @import("file_range_flags.zig").FileRangeFlags;

test {
    _ = std.testing.refAllDecls(@This());
}
