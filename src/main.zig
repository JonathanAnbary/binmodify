const std = @import("std");

const binmodify = @import("binmodify");

const ElfModder = binmodify.ElfModder;
const CoffModder = binmodify.CoffModder;
const ElfParsed = binmodify.ElfParsed;
const CoffParsed = binmodify.CoffParsed;
const arch = binmodify.arch;
const patch = binmodify.patch;

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

    var buf: [4]u8 = undefined;
    if ((try stream.read(buf[0..MZ.len])) != MZ.len) return Error.FileTypeNotSupported;
    if (std.mem.eql(u8, buf[0..MZ.len], MZ)) {
        const data = try alloc.alloc(u8, try stream.getEndPos());
        defer alloc.free(data);
        const coff = try std.coff.Coff.init(data, false);
        const parsed = CoffParsed.init(coff);
        var patcher = try patch.Patcher(CoffModder).init(alloc, &stream, &parsed);
        defer patcher.deinit(alloc);
        std.debug.print("Performing pure patch at addr {X}, patch {X}\n", .{ patch_addr, wanted_patch });
        try patcher.pure_patch(patch_addr, wanted_patch, &stream);
        std.debug.print("Patch done\n", .{});
    } else {
        if ((try stream.read(buf[MZ.len..ELF.len])) != (ELF.len - MZ.len)) return Error.FileTypeNotSupported;
        if (std.mem.eql(u8, buf[0..ELF.len], ELF)) {
            const parsed = try ElfParsed.init(&stream);
            var patcher = try patch.Patcher(ElfModder).init(alloc, &stream, &parsed);
            defer patcher.deinit(alloc);
            std.debug.print("Performing pure patch at addr {X}, patch {X}\n", .{ patch_addr, wanted_patch });
            try patcher.pure_patch(patch_addr, wanted_patch, &stream);
            std.debug.print("Patch done\n", .{});
        }
    }
}
