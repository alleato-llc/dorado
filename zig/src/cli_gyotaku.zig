//! The gyotaku CLI: Skein-512 file hashing, streaming in constant memory. Named for
//! the Japanese art of fish-printing: a file's fingerprint.

const std = @import("std");
const dorado = @import("dorado");
const skein = dorado.skein;

fn die(comptime msg: []const u8, args: anytype) noreturn {
    std.debug.print("error: " ++ msg ++ "\n", args);
    std.process.exit(1);
}

const VERSION = "0.1.0";

const USAGE =
    \\gyotaku 0.1.0
    \\Skein-512 file hashing, a fish-print fingerprint. Educational, unaudited.
    \\
    \\Usage: gyotaku [flags] [FILES...]
    \\
    \\Hashes each FILE with Skein-512, or stdin when no files are given.
    \\
    \\Flags:
    \\  --bits <n>        Output length in bits, a multiple of 8 (default 256).
    \\  --tag             Print BSD-style tagged output: "SKEIN-512 (file) = digest".
    \\  -c, --check       Read digests from the FILES and verify them (not implemented).
    \\  -h, --help        Print this help and exit.
    \\      --version     Print the version and exit.
    \\
;

fn printAndExit(io: std.Io, text: []const u8) noreturn {
    var stdout = std.Io.File.stdout();
    var wbuf: [4096]u8 = undefined;
    var fw = stdout.writer(io, &wbuf);
    fw.interface.writeAll(text) catch {};
    fw.interface.flush() catch {};
    std.process.exit(0);
}

fn digestStream(io: std.Io, file: std.Io.File, out_len: usize, out: []u8) !void {
    var rbuf: [64 * 1024]u8 = undefined;
    var fr = file.reader(io, &rbuf);
    var h = skein.Skein512.init(out_len);
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const n = fr.interface.readSliceShort(&chunk) catch break;
        if (n == 0) break;
        h.update(chunk[0..n]);
    }
    h.finalize(out);
}

pub fn main(init: std.process.Init) !void {
    const a = init.gpa;
    const io = init.io;

    var arglist: std.ArrayList([]const u8) = .empty;
    defer arglist.deinit(a);
    var it = std.process.Args.Iterator.init(init.minimal.args);
    _ = it.next(); // argv[0]
    var bits: usize = 256;
    var tag = false;
    var files: std.ArrayList([]const u8) = .empty;
    defer files.deinit(a);
    while (it.next()) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            printAndExit(io, USAGE);
        } else if (std.mem.eql(u8, arg, "--version")) {
            printAndExit(io, "gyotaku " ++ VERSION ++ "\n");
        } else if (std.mem.eql(u8, arg, "--bits")) {
            const v = it.next() orelse die("--bits needs a value", .{});
            bits = std.fmt.parseInt(usize, v, 10) catch die("invalid --bits", .{});
        } else if (std.mem.eql(u8, arg, "--tag")) {
            tag = true;
        } else if (std.mem.eql(u8, arg, "-c") or std.mem.eql(u8, arg, "--check")) {
            die("--check is not implemented in the Zig build", .{});
        } else {
            try files.append(a, arg);
        }
    }

    if (bits == 0 or bits % 8 != 0) die("--bits must be a positive multiple of 8", .{});
    const out_len = bits / 8;
    if (out_len > 1024) die("--bits too large", .{});

    var stdout_file = std.Io.File.stdout();
    var wbuf: [4096]u8 = undefined;
    var fw = stdout_file.writer(io, &wbuf);
    const w = &fw.interface;

    var out: [1024]u8 = undefined;
    if (files.items.len == 0) {
        digestStream(io, std.Io.File.stdin(), out_len, out[0..out_len]) catch die("read error", .{});
        if (tag) {
            try w.print("SKEIN-512 (-) = {x}\n", .{out[0..out_len]});
        } else {
            try w.print("{x}\n", .{out[0..out_len]});
        }
    } else {
        const cwd = std.Io.Dir.cwd();
        for (files.items) |path| {
            const f = cwd.openFile(io, path, .{}) catch {
                std.debug.print("error: {s}: cannot open\n", .{path});
                continue;
            };
            defer f.close(io);
            digestStream(io, f, out_len, out[0..out_len]) catch {
                std.debug.print("error: {s}: read error\n", .{path});
                continue;
            };
            if (tag) {
                try w.print("SKEIN-512 ({s}) = {x}\n", .{ path, out[0..out_len] });
            } else {
                try w.print("{x}  {s}\n", .{ out[0..out_len], path });
            }
        }
    }
    try w.flush();
}
