const builtin = @import("builtin");
const std = @import("std");

const binmodify = @import("binmodify");

const ElfParsed = binmodify.ElfParsed;
const ElfModder = binmodify.ElfModder;
const CoffParsed = binmodify.CoffParsed;
const CoffModder = binmodify.CoffModder;
const Patcher = binmodify.patch.Patcher;

const capstone = @import("capstone.zig");

test "elf nop patch no difference" {
    if (builtin.os.tag != .linux) {
        return error.SkipZigTest;
    }
    const test_src_path = "./tests/hello_world.zig";
    const test_with_patch_path = "./elf_nop_patch_no_difference";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-O", "ReleaseSmall", "-ofmt=elf", "-femit-bin=" ++ test_with_patch_path[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    // check regular output.
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);

    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        const patch = [_]u8{0x90} ** 0x900; // not doing 1000 since the cave size is only 1000 and we need some extra for the overwritten instructions and such.
        const parsed = try ElfParsed.init(&stream);
        var patcher: Patcher(ElfModder, capstone.Disasm) = try .init(std.testing.allocator, &stream, &parsed);
        defer patcher.deinit(std.testing.allocator);
        _ = try patcher.pure_patch(0x1001B34, &patch, &stream);
    }

    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(patch_result.term == .Exited);
    try std.testing.expect(no_patch_result.term == .Exited);
    try std.testing.expectEqual(patch_result.term.Exited, no_patch_result.term.Exited);
    try std.testing.expectEqualStrings(patch_result.stdout, no_patch_result.stdout);
    try std.testing.expectEqualStrings(patch_result.stderr, no_patch_result.stderr);
}

test "coff nop patch no difference" {
    if (builtin.os.tag != .windows) {
        return error.SkipZigTest;
    }
    const test_src_path = "./tests/hello_world.zig";
    const test_with_patch_path = "./coff_nop_patch_no_difference.exe";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-O", "ReleaseSmall", "-target", "x86_64-windows", "-ofmt=coff", "-femit-bin=" ++ test_with_patch_path[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    // check regular output.
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{ "wine", test_with_patch_path },
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);

    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        const patch = [_]u8{0x90} ** 0x90;
        const data = try std.testing.allocator.alloc(u8, try stream.getEndPos());
        defer std.testing.allocator.free(data);
        try std.testing.expectEqual(stream.getEndPos(), try stream.read(data));
        const coff = try std.coff.Coff.init(data, false);
        const parsed = CoffParsed.init(coff);
        var patcher: Patcher(CoffModder, capstone.Disasm) = try .init(std.testing.allocator, &stream, &parsed);
        defer patcher.deinit(std.testing.allocator);
        try patcher.pure_patch(0x1400011BB, &patch, &stream);
    }

    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{ "wine", test_with_patch_path },
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(patch_result.term == .Exited);
    try std.testing.expect(no_patch_result.term == .Exited);
    try std.testing.expectEqual(patch_result.term.Exited, no_patch_result.term.Exited);
    try std.testing.expectEqualStrings(patch_result.stdout, no_patch_result.stdout);
    try std.testing.expectEqualStrings(patch_result.stderr, no_patch_result.stderr);
}

test "elf fizzbuzz fizz always" {
    if (builtin.os.tag != .linux) {
        return error.SkipZigTest;
    }
    const test_src_path = "./tests/fizzbuzz.zig";
    const test_with_patch_path = "./elf_fizzbuzz_fizz_always";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-O", "ReleaseSmall", "-ofmt=elf", "-femit-bin=" ++ test_with_patch_path[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    const expected_output =
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\
    ;

    // check regular output.
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);

    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        try stream.seekTo(0xE55);
        const overwrite = [_]u8{0x83}; // changing jz to jae
        try std.testing.expectEqual(overwrite.len, try stream.write(&overwrite));
        const patch = [_]u8{ 0xFE, 0xC3 } ** 0x2; // inc bl; inc bl;
        const parsed = try ElfParsed.init(&stream);
        var patcher: Patcher(ElfModder, capstone.Disasm) = try .init(std.testing.allocator, &stream, &parsed);
        defer patcher.deinit(std.testing.allocator);
        _ = try patcher.pure_patch(0x1001E5A, &patch, &stream);
    }

    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{test_with_patch_path},
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(no_patch_result.term == .Exited);
    try std.testing.expect(patch_result.term == .Exited);
    try std.testing.expectEqual(no_patch_result.term.Exited, patch_result.term.Exited);
    try std.testing.expectEqualStrings(expected_output, patch_result.stdout);
    try std.testing.expectEqualStrings(no_patch_result.stderr, patch_result.stderr);
}

test "coff fizzbuzz fizz always" {
    if (builtin.os.tag != .windows) {
        return error.SkipZigTest;
    }
    const test_src_path = "./tests/fizzbuzz.zig";
    const test_with_patch_path = "./coff_fizzbuzz_fizz_always.exe";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_src_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-O", "ReleaseSmall", "-target", "x86_64-windows", "-ofmt=coff", "-femit-bin=" ++ test_with_patch_path[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_src_result.stdout);
        defer std.testing.allocator.free(build_src_result.stderr);
        try std.testing.expect(build_src_result.term == .Exited);
        try std.testing.expect(build_src_result.stderr.len == 0);
    }

    const expected_output =
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz Buzz
        \\Fizz
        \\Fizz
        \\Fizz
        \\Fizz
        \\
    ;

    // check regular output.
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{ "wine", test_with_patch_path },
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);

    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        try stream.seekTo(0x4E1);
        const overwrite = [_]u8{0x83}; // changing je to jae
        try std.testing.expectEqual(overwrite.len, try stream.write(&overwrite));
        try stream.seekTo(0);
        const patch = [_]u8{ 0x41, 0xFE, 0xC5 } ** 0x2; // inc r13b; inc r13b;
        const data = try std.testing.allocator.alloc(u8, try stream.getEndPos());
        defer std.testing.allocator.free(data);
        try std.testing.expectEqual(stream.getEndPos(), try stream.read(data));
        const coff = try std.coff.Coff.init(data, false);
        const parsed = CoffParsed.init(coff);
        var patcher: Patcher(CoffModder, capstone.Disasm) = try .init(std.testing.allocator, &stream, &parsed);
        defer patcher.deinit(std.testing.allocator);
        try patcher.pure_patch(0x1400010E6, &patch, &stream);
    }

    // check output with a cave
    const patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{ "wine", test_with_patch_path },
    });
    defer std.testing.allocator.free(patch_result.stdout);
    defer std.testing.allocator.free(patch_result.stderr);
    try std.testing.expect(no_patch_result.term == .Exited);
    try std.testing.expect(patch_result.term == .Exited);
    try std.testing.expectEqual(no_patch_result.term.Exited, patch_result.term.Exited);
    try std.testing.expectEqualStrings(expected_output, patch_result.stdout);
    try std.testing.expectEqualStrings(no_patch_result.stderr, patch_result.stderr);
}
