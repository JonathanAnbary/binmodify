const std = @import("std");

const config = @import("config");

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
