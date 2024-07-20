const std = @import("std");

// Although this function looks imperative, note that its job is to
// declaratively construct a build graph that will be executed by an external
// runner.
pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});

    const optimize = b.standardOptimizeOption(.{});

    const shared = b.option(bool, "shared", "Build as a shared library") orelse false;
    const strip = b.option(bool, "strip", "Omit debug information");
    const pic = b.option(bool, "pic", "Produce Position Independent Code");

    const capstone_dependency = b.dependency("capstone", .{
        .target = target,
        .optimize = optimize,
        .shared = shared,
        // .strip = strip,
        // .pic = pic,
    });

    const lib_mod = b.addModule("binmodify", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
        .strip = strip,
        .pic = pic,
    });

    lib_mod.linkLibrary(capstone_dependency.artifact("capstone"));

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
        .pic = pic,
        .strip = strip,
    });

    exe_mod.addImport("binmodify", lib_mod);

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

    const test_filters: []const []const u8 = b.option(
        []const []const u8,
        "test-filter",
        "Skip tests that do not match any of the specified filters",
    ) orelse &.{};

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("src/tests.zig"),
        .target = target,
        .optimize = optimize,
        .filters = test_filters,
        .pic = pic,
        .strip = strip,
    });
    unit_tests.linkLibrary(capstone_dependency.artifact("capstone"));
    unit_tests.addObjectFile(b.path("keystone/build/llvm/lib64/libkeystone.a"));
    unit_tests.addIncludePath(b.path("keystone/include/keystone/"));
    unit_tests.linkLibC();
    unit_tests.linkLibCpp();

    const run_unit_tests = b.addRunArtifact(unit_tests);

    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
