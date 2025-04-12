const std = @import("std");
const builtin = @import("builtin");

pub const patch = @import("patch.zig");
pub const ElfModder = @import("elf/Modder.zig");
pub const ElfParsed = @import("elf/Parsed.zig");
pub const CoffModder = @import("coff/Modder.zig");
pub const CoffParsed = @import("coff/Parsed.zig");
pub const arch = @import("arch.zig");
pub const FileRangeFlags = @import("file_range_flags.zig").FileRangeFlags;

pub const Disasm = @import("capstone.zig").Disasm;

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
    OverlappingMemoryRanges,
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
    NoSpaceToExtendPhdrTable,
    TooManyFileRanges,
    PatchTooLarge,
};

const AllError = patch.Error || ElfModder.Error || CoffModder.Error || Disasm.Error || arch.Error;

pub fn err_to_res(e: AllError) Result {
    return switch (e) {
        AllError.BrokenPipe => .BrokenPipe,
        AllError.ConnectionResetByPeer => .ConnectionResetByPeer,
        AllError.ConnectionTimedOut => .ConnectionTimedOut,
        AllError.NotOpenForReading => .NotOpenForReading,
        AllError.SocketNotConnected => .SocketNotConnected,
        AllError.WouldBlock => .WouldBlock,
        AllError.Canceled => .Canceled,
        AllError.AccessDenied => .AccessDenied,
        AllError.ProcessNotFound => .ProcessNotFound,
        AllError.LockViolation => .LockViolation,
        AllError.Unexpected => .Unexpected,
        AllError.NoSpaceLeft => .NoSpaceLeft,
        AllError.DiskQuota => .DiskQuota,
        AllError.FileTooBig => .FileTooBig,
        AllError.DeviceBusy => .DeviceBusy,
        AllError.InvalidArgument => .InvalidArgument,
        AllError.NotOpenForWriting => .NotOpenForWriting,
        AllError.NoDevice => .NoDevice,
        AllError.Unseekable => .Unseekable,
        AllError.UNKNOWN_CS_ERR => .UNKNOWN_CS_ERR,
        AllError.ArchNotSupported => .ArchNotSupported,
        AllError.ModeNotSupported => .ModeNotSupported,
        AllError.ArchEndianMismatch => .ArchEndianMismatch,
        AllError.AddrNotMapped => .AddrNotMapped,
        AllError.NoMatchingOffset => .NoMatchingOffset,
        AllError.OffsetNotLoaded => .OffsetNotLoaded,
        AllError.NoCaveOption => .NoCaveOption,
        AllError.InvalidPEMagic => .InvalidPEMagic,
        AllError.InvalidPEHeader => .InvalidPEHeader,
        AllError.InvalidMachine => .InvalidMachine,
        AllError.MissingPEHeader => .MissingPEHeader,
        AllError.MissingCoffSection => .MissingCoffSection,
        AllError.MissingStringTable => .MissingStringTable,
        AllError.EdgeNotFound => .EdgeNotFound,
        AllError.InvalidEdge => .InvalidEdge,
        AllError.InvalidHeader => .InvalidHeader,
        AllError.InvalidElfMagic => .InvalidElfMagic,
        AllError.InvalidElfVersion => .InvalidElfVersion,
        AllError.InvalidElfEndian => .InvalidElfEndian,
        AllError.InvalidElfClass => .InvalidElfClass,
        AllError.EndOfStream => .EndOfStream,
        AllError.OutOfMemory => .OutOfMemory,
        AllError.InputOutput => .InputOutput,
        AllError.SystemResources => .SystemResources,
        AllError.IsDir => .IsDir,
        AllError.OperationAborted => .OperationAborted,
        AllError.CS_ERR_MEM => .CS_ERR_MEM,
        AllError.CS_ERR_ARCH => .CS_ERR_ARCH,
        AllError.CS_ERR_HANDLE => .CS_ERR_HANDLE,
        AllError.CS_ERR_CSH => .CS_ERR_CSH,
        AllError.CS_ERR_MODE => .CS_ERR_MODE,
        AllError.CS_ERR_OPTION => .CS_ERR_OPTION,
        AllError.CS_ERR_DETAIL => .CS_ERR_DETAIL,
        AllError.CS_ERR_MEMSETUP => .CS_ERR_MEMSETUP,
        AllError.CS_ERR_VERSION => .CS_ERR_VERSION,
        AllError.CS_ERR_DIET => .CS_ERR_DIET,
        AllError.CS_ERR_SKIPDATA => .CS_ERR_SKIPDATA,
        AllError.CS_ERR_X86_ATT => .CS_ERR_X86_ATT,
        AllError.CS_ERR_X86_INTEL => .CS_ERR_X86_INTEL,
        AllError.CS_ERR_X86_MASM => .CS_ERR_X86_MASM,
        AllError.ArchNotEndianable => .ArchNotEndianable,
        AllError.ArchModeMismatch => .ArchModeMismatch,
        AllError.NoFreeSpace => .NoFreeSpace,
        AllError.InvalidOptionalHeaderMagic => .InvalidOptionalHeaderMagic,
        AllError.IntersectingFileRanges => .IntersectingFileRanges,
        AllError.OverlappingMemoryRanges => .OverlappingMemoryRanges,
        AllError.UnexpectedEof => .UnexpectedEof,
        AllError.VirtualSizeLessThenFileSize => .VirtualSizeLessThenFileSize,
        AllError.InvalidElfRanges => .InvalidElfRanges,
        AllError.CantExpandPhdr => .CantExpandPhdr,
        AllError.FileszBiggerThenMemsz => .FileszBiggerThenMemsz,
        AllError.StartAfterEnd => .StartAfterEnd,
        AllError.OutOfBoundField => .OutOfBoundField,
        AllError.UnmappedRange => .UnmappedRange,
        AllError.FieldNotAdjustable => .FieldNotAdjustable,
        AllError.PhdrTablePhdrNotFound => .PhdrTablePhdrNotFound,
        AllError.NoSpaceToExtendPhdrTable => .NoSpaceToExtendPhdrTable,
        AllError.TooManyFileRanges => .TooManyFileRanges,
        AllError.PatchTooLarge => .PatchTooLarge,
    };
}

fn inner_ElfPatcher_init(out: *patch.Patcher(ElfModder, Disasm), stream: *std.io.StreamSource) !void {
    const parsed = try ElfParsed.init(stream);
    out.* = try .init(alloc, stream, &parsed);
}

pub export fn ElfPatcher_init(out: *patch.Patcher(ElfModder, Disasm), stream: *std.io.StreamSource) Result {
    inner_ElfPatcher_init(out, stream) catch |err| return err_to_res(err);
    return .Ok;
}

pub export fn ElfPatcher_deinit(patcher: *patch.Patcher(ElfModder, Disasm)) void {
    patcher.deinit(alloc);
}

pub export fn ElfPatcher_pure_patch(patcher: *patch.Patcher(ElfModder, Disasm), addr: u64, patch_data: [*:0]const u8, stream: *std.io.StreamSource, maybe_patch_info: ?*patch.PatchInfo) Result {
    if (maybe_patch_info) |patch_info| {
        patch_info.* = patcher.pure_patch(addr, std.mem.span(patch_data), stream) catch |err| return err_to_res(err);
    } else {
        _ = patcher.pure_patch(addr, std.mem.span(patch_data), stream) catch |err| return err_to_res(err);
    }
    return .Ok;
}

fn inner_CoffPatcher_init(out: *patch.Patcher(CoffModder, Disasm), stream: *std.io.StreamSource) !void {
    const data = try alloc.alloc(u8, try stream.getEndPos());
    defer alloc.free(data);
    const coff = try std.coff.Coff.init(data, false);
    const parsed = CoffParsed.init(coff);
    out.* = try .init(alloc, stream, &parsed);
}

pub export fn CoffPatcher_init(out: *patch.Patcher(CoffModder, Disasm), stream: *std.io.StreamSource) Result {
    inner_CoffPatcher_init(out, stream) catch |err| return err_to_res(err);
    return .Ok;
}

pub export fn CoffPatcher_deinit(patcher: *patch.Patcher(CoffModder, Disasm)) void {
    patcher.deinit(alloc);
}

pub export fn CoffPatcher_pure_patch(patcher: *patch.Patcher(CoffModder, Disasm), addr: u64, patch_data: [*:0]const u8, stream: *std.io.StreamSource, maybe_patch_info: ?*patch.PatchInfo) Result {
    if (maybe_patch_info) |patch_info| {
        patch_info.* = patcher.pure_patch(addr, std.mem.span(patch_data), stream) catch |err| return err_to_res(err);
    } else {
        _ = patcher.pure_patch(addr, std.mem.span(patch_data), stream) catch |err| return err_to_res(err);
    }
    return .Ok;
}

test "c patcher api elf" {
    const test_src_path = "./tests/hello_world.zig";
    const test_with_patch_path = "./patcher_api_elf";
    const native_compile_path = "./c_elf_hello_world";
    const cwd: std.fs.Dir = std.fs.cwd();

    {
        const build_native_result = try std.process.Child.run(.{
            .allocator = std.testing.allocator,
            .argv = &[_][]const u8{ "zig", "build-exe", "-femit-bin=" ++ native_compile_path[2..], test_src_path },
        });
        defer std.testing.allocator.free(build_native_result.stdout);
        defer std.testing.allocator.free(build_native_result.stderr);
        try std.testing.expect(build_native_result.term == .Exited);
    }
    const no_patch_result = try std.process.Child.run(.{
        .allocator = std.testing.allocator,
        .argv = &[_][]const u8{native_compile_path},
    });
    defer std.testing.allocator.free(no_patch_result.stdout);
    defer std.testing.allocator.free(no_patch_result.stderr);
    try std.testing.expect(no_patch_result.term == .Exited);

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

    {
        var f = try cwd.openFile(test_with_patch_path, .{ .mode = .read_write });
        defer f.close();
        var stream = std.io.StreamSource{ .file = f };
        const patch_data: [*:0]const u8 = @ptrCast(&([_]u8{0x90} ** 0x900 ++ [_]u8{0x00})); // not doing 1000 since the cave size is only 1000 and we need some extra for the overwritten instructions and such.
        var patcher: patch.Patcher(ElfModder, Disasm) = undefined;
        const res = ElfPatcher_init(&patcher, &stream);
        try std.testing.expectEqual(.Ok, res);
        defer ElfPatcher_deinit(&patcher);
        try std.testing.expectEqual(.Ok, ElfPatcher_pure_patch(&patcher, 0x1001B43, patch_data, &stream, null));
    }

    if (builtin.os.tag != .linux) {
        return error.SkipZigTest;
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
