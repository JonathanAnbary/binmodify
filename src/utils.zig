const std = @import("std");

const config = @import("config");
const StreamSource = std.io.StreamSource;

pub fn should_add_test(gen_test_name: []const u8) bool {
    if (config.test_filters.len == 0) return true;
    @setEvalBranchQuota(5000);
    var add = false;
    for (config.test_filters) |filter| {
        if (std.mem.indexOf(u8, gen_test_name, filter) != null) {
            add = true;
            break;
        }
    }
    return add;
}

pub fn Index(T: type) type {
    return enum(u16) {
        _,

        const Self = @This();

        pub fn get(self: Self, items: [*]T) *T {
            return &items[@intFromEnum(self)];
        }

        pub fn next(self: Self) Self {
            return @enumFromInt(@intFromEnum(self) + 1);
        }

        pub fn prev(self: Self) Self {
            return @enumFromInt(@intFromEnum(self) - 1);
        }
    };
}

// The permissions that exist on a range of data in a file.
pub const FileRangeFlags: type = packed struct {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
};

pub const ShiftError = error{
    StartAfterEnd,
    UnexpectedEof,
};

pub fn shift_forward(stream: anytype, start: u64, end: u64, amt: u64) !void {
    if ((start == end) or (amt == 0)) return;
    if (start > end) return ShiftError.StartAfterEnd;
    var buff: [1024]u8 = undefined;
    const shift_start: u64 = blk: {
        if (end < (start + amt)) {
            const temp = try stream.getEndPos();
            if ((start + amt) > temp) {
                try stream.seekTo(temp);
                try stream.writer().writeByteNTimes(0, start + amt - temp);
            }
            break :blk start;
        } else break :blk end - amt;
    };
    var pos = shift_start;
    while ((pos + buff.len) < end) : (pos += buff.len) {
        try stream.seekTo(pos);
        if (try stream.read(&buff) != buff.len) return ShiftError.UnexpectedEof;
        try stream.seekTo(pos + amt);
        if (try stream.write(&buff) != buff.len) return ShiftError.UnexpectedEof;
    }
    try stream.seekTo(pos);
    if (try stream.read(buff[0 .. end - pos]) != end - pos) return ShiftError.UnexpectedEof;
    try stream.seekTo(pos + amt);
    if (try stream.write(buff[0 .. end - pos]) != end - pos) return ShiftError.UnexpectedEof;
    pos = shift_start;
    while (pos > (start + buff.len)) : (pos -= buff.len) {
        try stream.seekTo(pos - buff.len);
        if (try stream.read(&buff) != buff.len) return ShiftError.UnexpectedEof;
        try stream.seekTo(pos - buff.len + amt);
        if (try stream.write(&buff) != buff.len) return ShiftError.UnexpectedEof;
    }
    try stream.seekTo(start);
    if (try stream.read(buff[0 .. pos - start]) != pos - start) return ShiftError.UnexpectedEof;
    try stream.seekTo(start + amt);
    if (try stream.write(buff[0 .. pos - start]) != pos - start) return ShiftError.UnexpectedEof;
}

test "test shift stream" {
    const start = 0;
    const end = 10;
    const shift = 3;
    var buf = "abcdefghijklmnopqrstuvwxyz".*;
    var expected = "abcabcdefghijnopqrstuvwxyz".*;
    @memcpy(expected[start + shift .. end + shift], buf[start..end]);
    var stream = StreamSource{ .buffer = std.io.fixedBufferStream(&buf) };
    try shift_forward(&stream, start, end, shift);
    try std.testing.expectEqualStrings(&expected, &buf);
    const start2 = 0;
    const end2 = 4432;
    const shift2 = 1543;
    var buf2 = [1]u8{'A'} ** 1024 ++ "\n".* ++ [1]u8{'B'} ** 1024 ++ "\n".* ++ [1]u8{'C'} ** 1024 ++ "\n".* ++ [1]u8{'D'} ** 1024 ++ "\n".* ++ [1]u8{'E'} ** 1024 ++ "\n".* ++ [1]u8{'F'} ** 1024 ++ "\n".*;
    var expected2 = [1]u8{'A'} ** 1024 ++ "\n".* ++ [1]u8{'B'} ** 1024 ++ "\n".* ++ [1]u8{'C'} ** 1024 ++ "\n".* ++ [1]u8{'D'} ** 1024 ++ "\n".* ++ [1]u8{'E'} ** 1024 ++ "\n".* ++ [1]u8{'F'} ** 1024 ++ "\n".*;
    @memcpy(expected2[start2 + shift2 .. end2 + shift2], buf2[start2..end2]);
    var stream2 = StreamSource{ .buffer = std.io.fixedBufferStream(&buf2) };
    try shift_forward(&stream2, start2, end2, shift2);
    try std.testing.expectEqualStrings(&expected2, &buf2);
}
