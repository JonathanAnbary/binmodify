const std = @import("std");
const patch = @import("patch.zig");
const arch = @import("arch.zig");

fn arg_err(out: std.io.AnyWriter) !void {
    try out.print("MKPatch <file-to-patch> <patch-addr> <patch>", .{});
}

fn find_cave_err(out: std.io.AnyWriter) !void {
    try out.print("No Code cave found that fits request", .{});
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var args = std.process.args();
    _ = args.next() orelse return arg_err(stdout.any());
    const to_patch = args.next() orelse return arg_err(stdout.any());
    const patch_addr_str = args.next() orelse return arg_err(stdout.any());
    const patch_addr = std.fmt.parseUnsigned(u64, patch_addr_str, 0) catch |err| {
        return stdout.print("failed to parse {s} as u32 (err - {})\n", .{ patch_addr_str, err });
    };
    const wanted_patch_hex = args.next() orelse return arg_err(stdout.any());
    if (wanted_patch_hex.len == 0) return stdout.print("<patch> must be hex bytes", .{});
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() != std.heap.Check.ok) std.debug.panic("Program leaked", .{});
    const alloc = gpa.allocator();
    const patch_buf = try alloc.alloc(u8, @divFloor(wanted_patch_hex.len, 2));
    defer alloc.free(patch_buf);
    const wanted_patch = try std.fmt.hexToBytes(patch_buf, wanted_patch_hex);
    var f = try std.fs.cwd().openFile(to_patch, .{ .mode = .read_write });
    defer f.close();
    var stream = std.io.StreamSource{ .file = f };

    var patcher: patch.Patcher = try patch.Patcher.init(alloc, &stream, patch.FileType.Elf, arch.Arch.X86, arch.Mode.MODE_64, null);
    defer patcher.deinit(alloc) catch |err| std.debug.panic("Patcher deinit failed {}", .{err});
    std.debug.print("Performing pure patch at addr {X}, patch {X}\n", .{ patch_addr, wanted_patch });
    try patcher.pure_patch(patch_addr, wanted_patch);
    std.debug.print("Patch done\n", .{});
}
