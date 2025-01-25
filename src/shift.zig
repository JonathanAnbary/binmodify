const std = @import("std");
const StreamSource = std.io.StreamSource;

pub const Error = error{
    StartAfterEnd,
    UnexpectedEof,
};

pub fn shift_forward(stream: anytype, start: u64, end: u64, amt: u64) !void {
    if ((start == end) or (amt == 0)) return;
    if (start > end) return Error.StartAfterEnd;
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
        if (try stream.read(&buff) != buff.len) return Error.UnexpectedEof;
        try stream.seekTo(pos + amt);
        if (try stream.write(&buff) != buff.len) return Error.UnexpectedEof;
    }
    try stream.seekTo(pos);
    if (try stream.read(buff[0 .. end - pos]) != end - pos) return Error.UnexpectedEof;
    try stream.seekTo(pos + amt);
    if (try stream.write(buff[0 .. end - pos]) != end - pos) return Error.UnexpectedEof;
    pos = shift_start;
    while (pos > (start + buff.len)) : (pos -= buff.len) {
        try stream.seekTo(pos - buff.len);
        if (try stream.read(&buff) != buff.len) return Error.UnexpectedEof;
        try stream.seekTo(pos - buff.len + amt);
        if (try stream.write(&buff) != buff.len) return Error.UnexpectedEof;
    }
    try stream.seekTo(start);
    if (try stream.read(buff[0 .. pos - start]) != pos - start) return Error.UnexpectedEof;
    try stream.seekTo(start + amt);
    if (try stream.write(buff[0 .. pos - start]) != pos - start) return Error.UnexpectedEof;
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
