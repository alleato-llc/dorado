const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Default a release build to ReleaseSafe, not ReleaseFast: a security tool keeps
    // Zig's runtime safety checks (bounds, integer overflow, alignment) in the
    // shipped binary, so a bug that could leak a secret panics instead of becoming
    // silent undefined behavior. Plain `zig build` stays Debug for development;
    // `zig build --release` (or `-Doptimize=...`) selects the mode.
    const optimize = b.standardOptimizeOption(.{ .preferred_optimize_mode = .ReleaseSafe });

    // The library module (the SDK).
    const dorado_mod = b.addModule("dorado", .{
        .root_source_file = b.path("src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    // The two CLIs. The dorado CLI links libc only to mlock its password buffer
    // (keep it out of swap); the SDK module itself stays libc-free.
    const dorado_exe = b.addExecutable(.{
        .name = "dorado",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/cli_dorado.zig"),
            .target = target,
            .optimize = optimize,
            .link_libc = true,
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

    // Prove the primitives (Threefish/CTR, Skein, BLAKE3) build for a bare-metal
    // freestanding target with no OS and no allocator, like the Rust port's
    // bare-metal cipher crate. The engine (KDFs need an allocator) is excluded.
    const freestanding_obj = b.addObject(.{
        .name = "dorado-primitives",
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/primitives.zig"),
            .target = b.resolveTargetQuery(.{ .cpu_arch = .thumb, .os_tag = .freestanding, .abi = .eabi }),
            .optimize = .ReleaseSmall,
        }),
    });
    const freestanding_step = b.step("freestanding", "Build the primitives for a bare-metal target");
    freestanding_step.dependOn(&freestanding_obj.step);
}
