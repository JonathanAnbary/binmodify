const std = @import("std");
const elf = @import("elf.zig");

const Error = error{
    BadArguments,
};

pub fn main() !void {
    const stdout = std.io.getStdOut().writer();
    var args = std.process.args();
    _ = args.next() orelse {
        try stdout.print("MkPatch <file_to_patch> <file_offset>", .{});
        return Error.BadArguments;
    };
    const to_patch = args.next() orelse {
        try stdout.print("MkPatch <file_to_patch> <file_offset>", .{});
        return Error.BadArguments;
    };
    const file_offset_str = args.next() orelse {
        try stdout.print("MkPatch <file_to_patch> <file_offset>", .{});
        return Error.BadArguments;
    };
    const file_offset: u32 = std.fmt.parseUnsigned(
        u32,
        file_offset_str,
        0,
    ) catch |e| {
        try stdout.print("Bad file offset \"{s}\", err {}", .{ file_offset_str, e });
        return Error.BadArguments;
    };
    var f = try std.fs.cwd().openFile(to_patch, .{ .mode = .read_write });
    defer f.close();
    elf
}
