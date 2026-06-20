const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // The library module (the SDK).
    const dorado_mod = b.addModule("dorado", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // The two CLIs.
    const dorado_exe = b.addExecutable(.{
        .name = "dorado",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli_dorado.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "dorado", .module = dorado_mod }},
        }),
    });
    b.installArtifact(dorado_exe);

    const gyotaku_exe = b.addExecutable(.{
        .name = "gyotaku",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli_gyotaku.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "dorado", .module = dorado_mod }},
        }),
    });
    b.installArtifact(gyotaku_exe);

    // Tests: a separate module rooted at tests/ (so @embedFile reaches the
    // fixtures), importing the dorado library module.
    const tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("tests/test.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "dorado", .module = dorado_mod }},
        }),
    });
    const run_tests = b.addRunArtifact(tests);
    const test_step = b.step("test", "Run the test suite");
    test_step.dependOn(&run_tests.step);
}
