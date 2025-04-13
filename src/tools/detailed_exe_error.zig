const std = @import("std");
const windows = std.os.windows;

fn arg_err(out: std.io.AnyWriter) !void {
    try out.print("detailed_exe_error <exe-to-run>", .{});
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer if (gpa.deinit() != std.heap.Check.ok) std.debug.panic("Program leaked", .{});
    const alloc = gpa.allocator();

    const stdout = std.io.getStdOut().writer();
    const stderr = std.io.getStdErr().writer();

    var args = try std.process.argsWithAllocator(alloc);
    defer args.deinit();
    _ = args.next() orelse return arg_err(stderr.any());

    const to_run = args.next() orelse return arg_err(stderr.any());

    const app_name_w = try std.unicode.wtf8ToWtf16LeAllocZ(alloc, to_run);
    defer alloc.free(app_name_w);
    var siStartInfo = windows.STARTUPINFOW{
        .cb = @sizeOf(windows.STARTUPINFOW),
        .hStdError = null,
        .hStdOutput = null,
        .hStdInput = null,
        .dwFlags = windows.STARTF_USESTDHANDLES,

        .lpReserved = null,
        .lpDesktop = null,
        .lpTitle = null,
        .dwX = 0,
        .dwY = 0,
        .dwXSize = 0,
        .dwYSize = 0,
        .dwXCountChars = 0,
        .dwYCountChars = 0,
        .dwFillAttribute = 0,
        .wShowWindow = 0,
        .cbReserved2 = 0,
        .lpReserved2 = null,
    };
    var piProcInfo: windows.PROCESS_INFORMATION = undefined;
    if (windows.kernel32.CreateProcessW(
        app_name_w,
        null,
        null,
        null,
        windows.FALSE,
        0,
        null,
        null,
        &siStartInfo,
        &piProcInfo,
    ) == 0) {
        const err = windows.GetLastError();
        // 614 is the length of the longest windows error description
        var buf_wstr: [614:0]windows.WCHAR = undefined;
        const len = windows.kernel32.FormatMessageW(
            windows.FORMAT_MESSAGE_FROM_SYSTEM | windows.FORMAT_MESSAGE_IGNORE_INSERTS,
            null,
            err,
            (windows.SUBLANG.DEFAULT << 10) | windows.LANG.NEUTRAL,
            &buf_wstr,
            buf_wstr.len,
            null,
        );
        try stdout.print("CreateProcess failed GetLastError({}): {}", .{ err, std.unicode.fmtUtf16Le(buf_wstr[0..len]) });
    } else try stdout.print("Process spawned successfully.\n", .{});
}
