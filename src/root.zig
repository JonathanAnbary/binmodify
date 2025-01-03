const std = @import("std");
const testing = std.testing;

const arch = @import("arch.zig");
const patch = @import("patch.zig");
const modelf = @import("modelf.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const alloc = gpa.allocator();

const CErr = enum(u1) {
    Ok = 0,
    Leaked = 1,
};

const PatcherWrapper = extern struct {
    patcher: *patch.Patcher(modelf.ElfModder),
    stream: *std.io.StreamSource,
};

fn WrappedElfPatcher(filepath: [*c]const u8) ![*c]PatcherWrapper {
    const patcher_wrapper = try alloc.create(PatcherWrapper);
    errdefer alloc.destroy(patcher_wrapper);
    patcher_wrapper.stream = try alloc.create(std.io.StreamSource);
    errdefer alloc.destroy(patcher_wrapper.stream);
    patcher_wrapper.stream.* = std.io.StreamSource{ .file = try std.fs.cwd().openFile(std.mem.span(filepath), .{ .mode = .read_write }) };
    errdefer patcher_wrapper.stream.file.close();
    patcher_wrapper.patcher = try alloc.create(patch.Patcher(modelf.ElfModder));
    errdefer alloc.destroy(patcher_wrapper.patcher);
    patcher_wrapper.patcher.* = try patch.Patcher(modelf.ElfModder).init(alloc, patcher_wrapper.stream, arch.Arch.X86, arch.Mode.MODE_64, null);
    return patcher_wrapper;
}

export fn ElfPatcher_init(filepath: [*c]const u8) [*c]PatcherWrapper {
    const temp = WrappedElfPatcher(filepath) catch |err| {
        std.debug.print("failed to create ElfPatcher {any}\n", .{err});
        return null;
    };
    std.debug.print("{x}\n", .{@intFromPtr(temp)});
    return temp;
}

export fn ElfPatcher_code_patch(wraped_patcher: [*c]PatcherWrapper, addr: u64, code_patch: [*c]const u8) void {
    std.debug.print("{x}\n", .{@intFromPtr(wraped_patcher)});
    wraped_patcher.*.patcher.pure_patch(addr, std.mem.span(code_patch)) catch |err| std.debug.print("failed to pure_patch {any}\n", .{err});
}

export fn ElfPatcher_deinit(wraped_patcher: [*c]PatcherWrapper) void {
    std.debug.print("{x}\n", .{@intFromPtr(wraped_patcher)});
    wraped_patcher.*.stream.file.close();
    wraped_patcher.*.patcher.deinit(alloc) catch |err| std.debug.print("patcher deinit failed {any}\n", .{err});
    alloc.destroy(wraped_patcher.*.stream);
    alloc.destroy(wraped_patcher.*.patcher);
    alloc.destroy(@as(*PatcherWrapper, @ptrCast(wraped_patcher)));
}

test "elf nop patch no difference with api" {
    // NOTE: technically I could build the binary from source but I am unsure of a way to ensure that it will result in the exact same binary each time. (which would make the test flaky, since it might be that there is no viable code cave.).
    const test_path = "./tests/hello_world";
    const test_with_patch_path = "./elf_nop_patch_no_difference_with_api";
    const cwd: std.fs.Dir = std.fs.cwd();
    try cwd.copyFile(test_path, cwd, test_with_patch_path, .{});

    // check regular output.
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);

    // create cave.
    // NOTE: need to put this in a block since the file must be closed before the next process can execute.
    {
        const code_patch = [_]u8{0x90} ** 0x900 ++ [_]u8{0x00}; // not doing 1000 since the cave size is only 1000 and we need some extra for the overwritten instructions and such.
        const elfpatcher = ElfPatcher_init(@ptrCast(test_with_patch_path)).?;
        defer ElfPatcher_deinit(@as(*PatcherWrapper, @alignCast(@ptrCast(elfpatcher))));
        ElfPatcher_code_patch(@as(*PatcherWrapper, @alignCast(@ptrCast(elfpatcher))), 0x1001B3C, @as([*:0]const u8, @ptrCast(&code_patch)));
    }

    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(patch_result.term.Exited == no_patch_result.term.Exited);
    try std.testing.expectEqualStrings(patch_result.stdout, no_patch_result.stdout);
    try std.testing.expectEqualStrings(patch_result.stderr, no_patch_result.stderr);
}
