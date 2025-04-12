const std = @import("std");

const ElfModder = @import("elf/Modder.zig");
const CoffModder = @import("coff/Modder.zig");
const ElfParsed = @import("elf/Parsed.zig");
const CoffParsed = @import("coff/Parsed.zig");
const arch = @import("arch.zig");
const patch = @import("patch.zig");

const capstone = @import("capstone.zig");

fn arg_err(out: std.io.AnyWriter) !void {
    try out.print("binmodify <file-to-patch> <patch-addr> <patch>", .{});
}

fn find_cave_err(out: std.io.AnyWriter) !void {
    try out.print("No Code cave found that fits request", .{});
}

const MZ = "MZ";
const ELF = [_]u8{0x7F} ++ "ELF";

pub const Error = error{
    FileTypeNotSupported,
};

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() != std.heap.Check.ok) std.debug.panic("Program leaked", .{});
    const alloc = gpa.allocator();

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();
    _ = args.next() orelse return arg_err(stderr.any());

    const to_patch = args.next() orelse return arg_err(stderr.any());
    const patch_addr_str = args.next() orelse return arg_err(stderr.any());
    const patch_addr = std.fmt.parseUnsigned(u64, patch_addr_str, 0) catch |err| {
        return stderr.print("failed to parse {s} as u32 (err - {})\n", .{ patch_addr_str, err });
    };
    const wanted_patch_hex = args.next() orelse return arg_err(stderr.any());
    if (wanted_patch_hex.len == 0) return stderr.print("<patch> must be hex bytes", .{});
    const patch_buf = try alloc.alloc(u8, @divFloor(wanted_patch_hex.len, 2));
    defer alloc.free(patch_buf);
    const wanted_patch = try std.fmt.hexToBytes(patch_buf, wanted_patch_hex);
    var f = try std.fs.cwd().openFile(to_patch, .{ .mode = .read_write });
    defer f.close();

    var buf: [4]u8 = undefined;
    if ((try f.read(buf[0..MZ.len])) != MZ.len) return Error.FileTypeNotSupported;
    if (std.mem.eql(u8, buf[0..MZ.len], MZ)) {
        const data = try alloc.alloc(u8, try f.getEndPos());
        defer alloc.free(data);
        try f.seekTo(0);
        std.debug.assert(try f.readAll(data) == data.len);
        const coff = try std.coff.Coff.init(data, false);
        const parsed = CoffParsed.init(coff);
        var patcher = try patch.Patcher(CoffModder, capstone.Disasm).init(alloc, &f, &parsed);
        defer patcher.deinit(alloc);
        try stdout.print("Performing pure patch at addr {X}, patch {X}\n", .{ patch_addr, wanted_patch });
        _ = try patcher.pure_patch(patch_addr, wanted_patch, &f);
        try stdout.print("Patch done\n", .{});
    } else {
        if ((try f.read(buf[MZ.len..ELF.len])) != (ELF.len - MZ.len)) return Error.FileTypeNotSupported;
        if (std.mem.eql(u8, buf[0..ELF.len], ELF)) {
            const parsed = try ElfParsed.init(&f);
            var patcher = try patch.Patcher(ElfModder, capstone.Disasm).init(alloc, &f, &parsed);
            defer patcher.deinit(alloc);
            try stdout.print("Performing pure patch at addr {X}, patch {X}\n", .{ patch_addr, wanted_patch });
            _ = try patcher.pure_patch(patch_addr, wanted_patch, &f);
            try stdout.print("Patch done\n", .{});
        }
    }
}
