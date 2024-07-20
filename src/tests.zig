comptime {
    _ = @import("main.zig");
    _ = @import("root.zig");
    _ = @import("c_root.zig");
    _ = @import("modder/elf.zig");
    _ = @import("modder/coff.zig");
    _ = @import("modder/common.zig");
    _ = @import("patch.zig");
    _ = @import("ctl_asm.zig");
}
