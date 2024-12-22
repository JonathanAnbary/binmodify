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
    const wanted_patch = args.next() orelse return arg_err(stdout.any());
    var f = try std.fs.cwd().openFile(to_patch, .{ .mode = .read_write });
    defer f.close();
    var stream = std.io.StreamSource{ .file = f };

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() != std.heap.Check.ok) unreachable;
    const alloc = gpa.allocator();
    var patcher: patch.Patcher = try patch.Patcher.init(alloc, &stream, patch.FileType.Elf, arch.Arch.X86, arch.Mode.MODE_64, null);
    defer patcher.deinit(alloc) catch unreachable;
    try patcher.pure_patch(patch_addr, wanted_patch);
}
