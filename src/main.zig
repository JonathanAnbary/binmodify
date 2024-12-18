const std = @import("std");
const elf = @import("elf.zig");

fn arg_err(out: std.io.AnyWriter) !void {
    try out.print("MKPatch <file-to-patch> <file-offset>", .{});
}

fn find_cave_err(out: std.io.AnyWriter) !void {
    try out.print("No Code cave found that fits request", .{});
}

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var args = std.process.args();
    _ = args.next() orelse return arg_err(stdout.any());
    const to_patch = args.next() orelse return arg_err(stdout.any());
    // const file_offset_str = args.next() orelse break :blk;
    // const file_offset: u32 = std.fmt.parseUnsigned(
    //     u32,
    //     file_offset_str,
    //     0,
    // ) catch |err| {};
    var f = try std.fs.cwd().openFile(to_patch, .{ .mode = .read_write });
    defer f.close();
    var stream = std.io.StreamSource{ .file = f };
    var elf_modder: elf.ElfModder = try elf.ElfModder.init(&stream);
    const option = try elf_modder.get_cave_option(1000, elf.PType.PT_LOAD, elf.PFlags{ .PF_X = true, .PF_R = true }) orelse return find_cave_err(stdout.any());
    try stdout.print("found cave option {}\n", .{option});
    try elf_modder.create_cave(1000, option);
    try stdout.print("cave created succussfully.\n", .{});
}
