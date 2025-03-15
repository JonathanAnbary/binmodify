const std = @import("std");

// The permissions that exist on a range of data in a file.
pub const FileRangeFlags: type = packed struct {
    read: bool = false,
    write: bool = false,
    execute: bool = false,
};
