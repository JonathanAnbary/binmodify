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
    const wanted_size_str = args.next() orelse return arg_err(stdout.any());
    const wanted_size = std.fmt.parseUnsigned(u32, wanted_size_str, 0) catch |err| {
        return stdout.print("failed to parse {s} as u32 (err - {})\n", .{ wanted_size_str, err });
    };
    var f = try std.fs.cwd().openFile(to_patch, .{ .mode = .read_write });
    defer f.close();
    var stream = std.io.StreamSource{ .file = f };

    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() != std.heap.Check.ok) @panic("LEAKED");
    const alloc = gpa.allocator();
    var elf_modder: elf.ElfModder = try elf.ElfModder.init(alloc, &stream);
    defer elf_modder.deinit(alloc);
    const option = try elf_modder.get_cave_option(wanted_size, elf.PType.PT_LOAD, elf.PFlags{ .PF_X = true, .PF_R = true }) orelse return find_cave_err(stdout.any());
    try stdout.print("found cave option {}\n", .{option});
    try elf_modder.create_cave(alloc, wanted_size, option);
    try stdout.print("cave created succussfully.\n", .{});
}
