const std = @import("std");
const builtin = @import("builtin");

pub const patch = @import("patch.zig");
pub const ElfModder = @import("elf/Modder.zig");
pub const ElfParsed = @import("elf/Parsed.zig");
pub const CoffModder = @import("coff/Modder.zig");
pub const CoffParsed = @import("coff/Parsed.zig");
pub const common = @import("common.zig");

var gpa = std.heap.GeneralPurposeAllocator(.{}){};
const alloc = gpa.allocator();

pub const Result: type = enum(u8) {
    Ok = 0,
    UnknownFileType,
    BrokenPipe,
    ConnectionResetByPeer,
    ConnectionTimedOut,
    NotOpenForReading,
    SocketNotConnected,
    WouldBlock,
    Canceled,
    AccessDenied,
    ProcessNotFound,
    LockViolation,
    Unexpected,
    NoSpaceLeft,
    DiskQuota,
    FileTooBig,
    DeviceBusy,
    InvalidArgument,
    NotOpenForWriting,
    NoDevice,
    Unseekable,
    UNKNOWN_CS_ERR,
    ArchNotSupported,
    ModeNotSupported,
    ArchEndianMismatch,
    AddrNotMapped,
    NoMatchingOffset,
    OffsetNotLoaded,
    NoCaveOption,
    InvalidPEMagic,
    InvalidPEHeader,
    InvalidMachine,
    MissingPEHeader,
    MissingCoffSection,
    MissingStringTable,
    EdgeNotFound,
    InvalidEdge,
    InvalidHeader,
    InvalidElfMagic,
    InvalidElfVersion,
    InvalidElfEndian,
    InvalidElfClass,
    EndOfStream,
    OutOfMemory,
    InputOutput,
    SystemResources,
    IsDir,
    OperationAborted,
    CS_ERR_MEM,
    CS_ERR_ARCH,
    CS_ERR_HANDLE,
    CS_ERR_CSH,
    CS_ERR_MODE,
    CS_ERR_OPTION,
    CS_ERR_DETAIL,
    CS_ERR_MEMSETUP,
    CS_ERR_VERSION,
    CS_ERR_DIET,
    CS_ERR_SKIPDATA,
    CS_ERR_X86_ATT,
    CS_ERR_X86_INTEL,
    CS_ERR_X86_MASM,
    ArchNotEndianable,
    ArchModeMismatch,
    NoFreeSpace,
    InvalidOptionalHeaderMagic,
    IntersectingFileRanges,
    IntersectingMemoryRanges,
    IllogicalInsnToMove,
    IllogicalJmpSize,
    UnexpectedEof,
    VirtualSizeLessThenFileSize,
    InvalidElfRanges,
    CantExpandPhdr,
    FileszBiggerThenMemsz,
    StartAfterEnd,
    OutOfBoundField,
    UnmappedRange,
    FieldNotAdjustable,
    PhdrTablePhdrNotFound,
    NoSpacePastPhdrTable,
};

pub fn err_to_res(e: patch.Error) Result {
    return switch (e) {
        patch.Error.BrokenPipe => .BrokenPipe,
        patch.Error.ConnectionResetByPeer => .ConnectionResetByPeer,
        patch.Error.ConnectionTimedOut => .ConnectionTimedOut,
        patch.Error.NotOpenForReading => .NotOpenForReading,
        patch.Error.SocketNotConnected => .SocketNotConnected,
        patch.Error.WouldBlock => .WouldBlock,
        patch.Error.Canceled => .Canceled,
        patch.Error.AccessDenied => .AccessDenied,
        patch.Error.ProcessNotFound => .ProcessNotFound,
        patch.Error.LockViolation => .LockViolation,
        patch.Error.Unexpected => .Unexpected,
        patch.Error.NoSpaceLeft => .NoSpaceLeft,
        patch.Error.DiskQuota => .DiskQuota,
        patch.Error.FileTooBig => .FileTooBig,
        patch.Error.DeviceBusy => .DeviceBusy,
        patch.Error.InvalidArgument => .InvalidArgument,
        patch.Error.NotOpenForWriting => .NotOpenForWriting,
        patch.Error.NoDevice => .NoDevice,
        patch.Error.Unseekable => .Unseekable,
        patch.Error.UNKNOWN_CS_ERR => .UNKNOWN_CS_ERR,
        patch.Error.ArchNotSupported => .ArchNotSupported,
        patch.Error.ModeNotSupported => .ModeNotSupported,
        patch.Error.ArchEndianMismatch => .ArchEndianMismatch,
        patch.Error.AddrNotMapped => .AddrNotMapped,
        patch.Error.NoMatchingOffset => .NoMatchingOffset,
        patch.Error.OffsetNotLoaded => .OffsetNotLoaded,
        patch.Error.NoCaveOption => .NoCaveOption,
        patch.Error.InvalidPEMagic => .InvalidPEMagic,
        patch.Error.InvalidPEHeader => .InvalidPEHeader,
        patch.Error.InvalidMachine => .InvalidMachine,
        patch.Error.MissingPEHeader => .MissingPEHeader,
        patch.Error.MissingCoffSection => .MissingCoffSection,
        patch.Error.MissingStringTable => .MissingStringTable,
        patch.Error.EdgeNotFound => .EdgeNotFound,
        patch.Error.InvalidEdge => .InvalidEdge,
        patch.Error.InvalidHeader => .InvalidHeader,
        patch.Error.InvalidElfMagic => .InvalidElfMagic,
        patch.Error.InvalidElfVersion => .InvalidElfVersion,
        patch.Error.InvalidElfEndian => .InvalidElfEndian,
        patch.Error.InvalidElfClass => .InvalidElfClass,
        patch.Error.EndOfStream => .EndOfStream,
        patch.Error.OutOfMemory => .OutOfMemory,
        patch.Error.InputOutput => .InputOutput,
        patch.Error.SystemResources => .SystemResources,
        patch.Error.IsDir => .IsDir,
        patch.Error.OperationAborted => .OperationAborted,
        patch.Error.CS_ERR_MEM => .CS_ERR_MEM,
        patch.Error.CS_ERR_ARCH => .CS_ERR_ARCH,
        patch.Error.CS_ERR_HANDLE => .CS_ERR_HANDLE,
        patch.Error.CS_ERR_CSH => .CS_ERR_CSH,
        patch.Error.CS_ERR_MODE => .CS_ERR_MODE,
        patch.Error.CS_ERR_OPTION => .CS_ERR_OPTION,
        patch.Error.CS_ERR_DETAIL => .CS_ERR_DETAIL,
        patch.Error.CS_ERR_MEMSETUP => .CS_ERR_MEMSETUP,
        patch.Error.CS_ERR_VERSION => .CS_ERR_VERSION,
        patch.Error.CS_ERR_DIET => .CS_ERR_DIET,
        patch.Error.CS_ERR_SKIPDATA => .CS_ERR_SKIPDATA,
        patch.Error.CS_ERR_X86_ATT => .CS_ERR_X86_ATT,
        patch.Error.CS_ERR_X86_INTEL => .CS_ERR_X86_INTEL,
        patch.Error.CS_ERR_X86_MASM => .CS_ERR_X86_MASM,
        patch.Error.ArchNotEndianable => .ArchNotEndianable,
        patch.Error.ArchModeMismatch => .ArchModeMismatch,
        patch.Error.NoFreeSpace => .NoFreeSpace,
        patch.Error.InvalidOptionalHeaderMagic => .InvalidOptionalHeaderMagic,
        patch.Error.IntersectingFileRanges => .IntersectingFileRanges,
        patch.Error.IntersectingMemoryRanges => .IntersectingMemoryRanges,
        patch.Error.IllogicalInsnToMove => .IllogicalInsnToMove,
        patch.Error.IllogicalJmpSize => .IllogicalJmpSize,
        patch.Error.UnexpectedEof => .UnexpectedEof,
        patch.Error.VirtualSizeLessThenFileSize => .VirtualSizeLessThenFileSize,
        patch.Error.InvalidElfRanges => .InvalidElfRanges,
        patch.Error.CantExpandPhdr => .CantExpandPhdr,
        patch.Error.FileszBiggerThenMemsz => .FileszBiggerThenMemsz,
        patch.Error.StartAfterEnd => .StartAfterEnd,
        patch.Error.OutOfBoundField => .OutOfBoundField,
        patch.Error.UnmappedRange => .UnmappedRange,
        patch.Error.FieldNotAdjustable => .FieldNotAdjustable,
        patch.Error.PhdrTablePhdrNotFound => .PhdrTablePhdrNotFound,
        patch.Error.NoSpacePastPhdrTable => .NoSpacePastPhdrTable,
    };
}

fn inner_ElfPatcher_init(out: *patch.Patcher(ElfModder), stream: *std.io.StreamSource) !void {
    const parsed = try ElfParsed.init(stream);
    out.* = try patch.Patcher(ElfModder).init(alloc, stream, &parsed);
}

pub export fn ElfPatcher_init(out: *patch.Patcher(ElfModder), stream: *std.io.StreamSource) Result {
    inner_ElfPatcher_init(out, stream) catch |err| return err_to_res(err);
    return .Ok;
}

pub export fn ElfPatcher_deinit(patcher: *patch.Patcher(ElfModder)) void {
    patcher.deinit(alloc);
}

pub export fn ElfPatcher_pure_patch(patcher: *patch.Patcher(ElfModder), addr: u64, patch_data: [*:0]const u8, stream: *std.io.StreamSource) Result {
    patcher.pure_patch(addr, std.mem.span(patch_data), stream) catch |err| return err_to_res(err);
    return .Ok;
}

fn inner_CoffPatcher_init(out: *patch.Patcher(CoffModder), stream: *std.io.StreamSource) !void {
    const data = try alloc.alloc(u8, try stream.getEndPos());
    defer alloc.free(data);
    const coff = try std.coff.Coff.init(data, false);
    const parsed = CoffParsed.init(coff);
    out.* = try patch.Patcher(CoffModder).init(alloc, stream, &parsed);
}

pub export fn CoffPatcher_init(out: *patch.Patcher(CoffModder), stream: *std.io.StreamSource) Result {
    inner_CoffPatcher_init(out, stream) catch |err| return err_to_res(err);
    return .Ok;
}

pub export fn CoffPatcher_deinit(patcher: *patch.Patcher(CoffModder)) void {
    patcher.deinit(alloc);
}

pub export fn CoffPatcher_pure_patch(patcher: *patch.Patcher(CoffModder), addr: u64, patch_data: [*:0]const u8, stream: *std.io.StreamSource) Result {
    patcher.pure_patch(addr, std.mem.span(patch_data), stream) catch |err| return err_to_res(err);
    return .Ok;
}

test "c patcher api elf" {
    if (builtin.os.tag != .linux) {
        return error.SkipZigTest;
    }
    const test_src_path = "./tests/hello_world.zig";
    const test_with_patch_path = "./patcher_api_elf";
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
        const patch_data: [*:0]const u8 = @ptrCast(&([_]u8{0x90} ** 0x900 ++ [_]u8{0x00})); // not doing 1000 since the cave size is only 1000 and we need some extra for the overwritten instructions and such.
        var patcher: patch.Patcher(ElfModder) = undefined;
        const res = ElfPatcher_init(&patcher, &stream);
        try std.testing.expectEqual(.Ok, res);
        defer ElfPatcher_deinit(&patcher);
        try std.testing.expectEqual(.Ok, ElfPatcher_pure_patch(&patcher, 0x1001B43, patch_data, &stream));
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
