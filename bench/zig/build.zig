const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    // Benchmark raw throughput at full optimization (apples-to-apples with the Rust
    // release and C -O2 runners). The shipped Zig CLI defaults to ReleaseSafe; that
    // safety-check overhead is a separate concern from this throughput number.
    const optimize: std.builtin.OptimizeMode = .ReleaseFast;

    const dorado_mod = b.createModule(.{
        .root_source_file = b.path("../../zig/src/root.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "dorado-bench",
        .root_module = b.createModule(.{
            .root_source_file = b.path("main.zig"),
            .target = target,
            .optimize = optimize,
            .imports = &.{.{ .name = "dorado", .module = dorado_mod }},
        }),
    });
    b.installArtifact(exe);
}
