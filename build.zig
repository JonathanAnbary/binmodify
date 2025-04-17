const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const shared = b.option(bool, "shared", "Build as a shared library") orelse false;
    const strip = b.option(bool, "strip", "Omit debug information");
    const pic = b.option(bool, "pic", "Produce Position Independent Code");
    const test_filters: []const []const u8 = b.option(
        []const []const u8,
        "test-filter",
        "Skip tests that do not match any of the specified filters",
    ) orelse &.{};

    const options = b.addOptions();
    options.addOption([]const []const u8, "test_filters", test_filters);

    const capstone_dependency = b.dependency("capstone", .{
        .target = target,
        .optimize = optimize,
        .shared = shared,
    });

    const lib_mod = b.addModule("binmodify", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .pic = pic,
    });

    lib_mod.addOptions("config", options);

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = pic,
        .strip = strip,
    });

    exe_mod.linkLibrary(capstone_dependency.artifact("capstone"));
    exe_mod.addImport("binmodify", lib_mod);
    exe_mod.addOptions("config", options);

    const exe = b.addExecutable(.{
        .name = "binmodify",
        .root_module = exe_mod,
    });

    b.installArtifact(exe);

    const clib_mod = b.addModule("cbinmodify", .{
        .root_source_file = b.path("src/c_root.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .pic = pic,
    });

    clib_mod.addOptions("config", options);

    clib_mod.linkLibrary(capstone_dependency.artifact("capstone"));

    const clib = std.Build.Step.Compile.create(b, .{
        .name = "binmodify",
        .kind = .lib,
        .linkage = if (shared) .dynamic else .static,
        .root_module = clib_mod,
    });

    b.installArtifact(clib);

    const run_cmd = b.addRunArtifact(exe);

    run_cmd.step.dependOn(b.getInstallStep());

    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const tests_mod = b.createModule(.{
        .root_source_file = b.path("src/c_root.zig"),
        .target = target,
        .optimize = optimize,
        .pic = pic,
        .strip = strip,
        .link_libc = true,
        .link_libcpp = true,
    });

    tests_mod.addOptions("config", options);

    const all_tests = b.addTest(.{
        .root_module = tests_mod,
        .filters = test_filters,
    });
    all_tests.linkLibrary(capstone_dependency.artifact("capstone"));
    all_tests.addObjectFile(b.path("keystone/build/llvm/lib64/libkeystone.a"));
    all_tests.addIncludePath(b.path("keystone/include/keystone/"));

    const run_unit_tests = b.addRunArtifact(all_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
