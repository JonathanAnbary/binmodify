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
