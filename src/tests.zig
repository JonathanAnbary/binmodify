comptime {
    _ = @import("main.zig");
    _ = @import("root.zig");
    _ = @import("c_root.zig");
    _ = @import("elf/Modder.zig");
    _ = @import("elf/Parsed.zig");
    _ = @import("coff/Modder.zig");
    _ = @import("coff/Parsed.zig");
    _ = @import("patch.zig");
    _ = @import("ctl_asm.zig");
}
