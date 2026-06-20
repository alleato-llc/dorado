//! Zig throughput runner. Times the from-scratch primitives under the uniform
//! protocol (see ../README.md) and emits one JSON line per benchmark.

const std = @import("std");
const dorado = @import("dorado");

fn nowS(io: std.Io) f64 {
    const ns: i96 = std.Io.Clock.now(.awake, io).toNanoseconds();
    return @as(f64, @floatFromInt(ns)) / 1e9;
}

const Op = enum { ctr256, ctr512, ctr1024, skein, blake3 };

fn runOp(op: Op, data: []u8, out32: *[32]u8) void {
    switch (op) {
        .ctr256 => {
            var c = dorado.threefish.Threefish.init(.t256, &([_]u8{7} ** 32), &([_]u8{0} ** 16));
            var ctr = c.newCtr(&([_]u8{1} ** 32));
            ctr.apply(data);
        },
        .ctr512 => {
            var c = dorado.threefish.Threefish.init(.t512, &([_]u8{7} ** 64), &([_]u8{0} ** 16));
            var ctr = c.newCtr(&([_]u8{1} ** 64));
            ctr.apply(data);
        },
        .ctr1024 => {
            var c = dorado.threefish.Threefish.init(.t1024, &([_]u8{7} ** 128), &([_]u8{0} ** 16));
            var ctr = c.newCtr(&([_]u8{1} ** 128));
            ctr.apply(data);
        },
        .skein => dorado.skein.hash(32, data, out32),
        .blake3 => dorado.blake3.hash(32, data, out32),
    }
}

fn bench(io: std.Io, name: []const u8, op: Op, data: []u8, warmup: f64, measure: f64, w: *std.Io.Writer) !void {
    var out32: [32]u8 = undefined;
    var start = nowS(io);
    while (nowS(io) - start < warmup) runOp(op, data, &out32);
    start = nowS(io);
    var iters: u64 = 0;
    while (nowS(io) - start < measure) {
        runOp(op, data, &out32);
        iters += 1;
    }
    const elapsed = nowS(io) - start;
    const mbps = @as(f64, @floatFromInt(data.len)) * @as(f64, @floatFromInt(iters)) / 1e6 / elapsed;
    try w.print("{{\"impl\":\"zig\",\"bench\":\"{s}\",\"mbps\":{d:.2},\"iters\":{d}}}\n", .{ name, mbps, iters });
}

pub fn main(init: std.process.Init) !void {
    const a = init.gpa;
    const io = init.io;

    var args: std.ArrayList([]const u8) = .empty;
    defer args.deinit(a);
    var it = std.process.Args.Iterator.init(init.minimal.args);
    while (it.next()) |arg| try args.append(a, arg);

    const buf_bytes: usize = if (args.items.len > 1) try std.fmt.parseInt(usize, args.items[1], 10) else 1048576;
    const warmup: f64 = if (args.items.len > 2) try std.fmt.parseFloat(f64, args.items[2]) else 0.5;
    const measure: f64 = if (args.items.len > 3) try std.fmt.parseFloat(f64, args.items[3]) else 2.0;

    const data = try a.alloc(u8, buf_bytes);
    defer a.free(data);
    @memset(data, 0);

    var stdout = std.Io.File.stdout();
    var wbuf: [4096]u8 = undefined;
    var fw = stdout.writer(io, &wbuf);
    const w = &fw.interface;

    try bench(io, "threefish-256-ctr", .ctr256, data, warmup, measure, w);
    try bench(io, "threefish-512-ctr", .ctr512, data, warmup, measure, w);
    try bench(io, "threefish-1024-ctr", .ctr1024, data, warmup, measure, w);
    try bench(io, "skein-512", .skein, data, warmup, measure, w);
    try bench(io, "blake3", .blake3, data, warmup, measure, w);
    try w.flush();
}
