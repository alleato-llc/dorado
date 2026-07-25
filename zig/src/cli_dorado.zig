//! The dorado CLI: encrypt/decrypt/inspect, raw-key and password modes, streaming
//! over std.Io.File. A port of the Rust/Go CLIs (no GUI).
//!
//! Both key modes are authenticated (encrypt-then-MAC) by default: password mode
//! always, and raw-key mode (--key/--key-file) via the raw authenticated
//! construction, so a tampered, corrupted, or wrong-key stream is rejected on
//! decrypt rather than silently producing garbage. --unauthenticated opts raw-key
//! mode back into bare CTR (no container, no authentication, output length equals
//! input length exactly) -- a deliberate, expert opt-out, not the default, since
//! a corrupted or tampered byte in that mode silently decrypts to a flipped
//! plaintext byte with no error of any kind.

const std = @import("std");
const dorado = @import("dorado");
const engine = dorado.engine;
const fmt = dorado.format;

// POSIX mlock/munlock (libc), to keep the password buffer out of swap.
extern "c" fn mlock(addr: *const anyopaque, len: usize) c_int;
extern "c" fn munlock(addr: *const anyopaque, len: usize) c_int;

// Best-effort: disable core dumps for this process before any secret exists.
//
// We already mlock the password buffer (see crypt below), but mlock only keeps a
// page out of swap, not out of a core dump: if the process crashes, the kernel can
// write a core file that captures locked pages just like any other memory, spilling
// the password or derived keys to disk. Setting RLIMIT_CORE (soft and hard) to 0
// stops that core file from being written. (libsodium's secure allocator pairs
// mlock with madvise(MADV_DONTDUMP) for the same reason.) This is hardening, not a
// correctness requirement, so any error is ignored and we keep going. We do not
// touch ptrace / PR_SET_DUMPABLE: this CLI is short-lived, so we keep it simple and
// debuggable and just close the core-file path.
fn suppressCoreDumps() void {
    switch (@import("builtin").os.tag) {
        // No POSIX resource limits to set; nothing to do.
        .windows, .wasi => {},
        else => std.posix.setrlimit(.CORE, .{ .cur = 0, .max = 0 }) catch {},
    }
}

// Adapt a buffered std.Io.Reader to the engine's callback Reader.
const ReaderAdapter = struct {
    r: *std.Io.Reader,
    fn read(ctx: *anyopaque, buf: []u8) usize {
        const self: *ReaderAdapter = @ptrCast(@alignCast(ctx));
        return self.r.readSliceShort(buf) catch 0;
    }
    fn iface(self: *ReaderAdapter) engine.Reader {
        return .{ .ctx = self, .readFn = read };
    }
};

const WriterAdapter = struct {
    w: *std.Io.Writer,
    fn write(ctx: *anyopaque, bytes: []const u8) bool {
        const self: *WriterAdapter = @ptrCast(@alignCast(ctx));
        self.w.writeAll(bytes) catch return false;
        return true;
    }
    fn iface(self: *WriterAdapter) engine.Writer {
        return .{ .ctx = self, .writeFn = write };
    }
};

fn die(comptime msg: []const u8, args: anytype) noreturn {
    std.debug.print("error: " ++ msg ++ "\n", args);
    std.process.exit(1);
}

const VERSION = "0.1.0";

const USAGE =
    \\dorado 0.1.0
    \\Threefish in CTR mode, authenticated (encrypt-then-MAC) by default
    \\(educational, unaudited).
    \\
    \\Usage: dorado <encrypt|decrypt|inspect> [flags]
    \\
    \\Commands:
    \\  encrypt   Encrypt input with Threefish-CTR.
    \\  decrypt   Decrypt input with Threefish-CTR (the same operation as encrypt).
    \\  inspect   Print a password file's non-secret parameters without decrypting it.
    \\
    \\Key (one is required for encrypt/decrypt):
    \\  --key <hex>           Raw key as hex (32/64/128 bytes). Requires --iv.
    \\  --key-file <path>     Read the raw key hex from a file. Requires --iv.
    \\  --password            Derive the key from a password (prompted on the terminal).
    \\  --password-stdin      Read the password from stdin (use --in for the data).
    \\
    \\Common flags:
    \\  --iv <hex>            IV for raw-key mode (must match the block size).
    \\  --unauthenticated    Opt out of authentication for raw-key mode, falling
    \\                       back to bare CTR: confidentiality only, no tamper or
    \\                       corruption detection (a flipped ciphertext byte
    \\                       silently flips a plaintext byte). A deliberate,
    \\                       expert opt-out; not used in password mode, which is
    \\                       always authenticated.
    \\  --tweak <hex>         16-byte tweak (default all zero).
    \\  --variant <256|512|1024>   Threefish variant for password mode (default 256).
    \\  --kdf <argon2id|scrypt|pbkdf2>   KDF for password mode (default argon2id).
    \\  --mac <skein|hmac-sha256|blake3> MAC for password mode, or for raw-key
    \\                       mode unless --unauthenticated (default skein).
    \\  --chunk-kib <n>      Authenticated chunk size in KiB, for password mode and
    \\                       raw-key mode unless --unauthenticated (default 64).
    \\  --label <text>       Bind a non-secret label into the container.
    \\  --expect-label <text>   Require this label when decrypting.
    \\  --in <path>          Input file (default stdin).
    \\  --out <path>         Output file (default stdout).
    \\
    \\KDF tuning: --argon2-mem-mib, --argon2-time, --argon2-par,
    \\            --scrypt-logn, --scrypt-r, --scrypt-p, --pbkdf2-rounds.
    \\
    \\  -h, --help           Print this help and exit.
    \\      --version        Print the version and exit.
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

fn printHelp(io: std.Io) noreturn {
    printAndExit(io, USAGE);
}

fn printVersion(io: std.Io) noreturn {
    printAndExit(io, "dorado " ++ VERSION ++ "\n");
}

const Args = struct {
    command: []const u8 = "",
    key: ?[]const u8 = null,
    key_file: ?[]const u8 = null,
    iv: ?[]const u8 = null,
    tweak: []const u8 = "00000000000000000000000000000000",
    password: bool = false,
    password_stdin: bool = false,
    unauthenticated: bool = false,
    variant: []const u8 = "256",
    kdf: []const u8 = "argon2id",
    mac: []const u8 = "skein",
    argon2_mem: u32 = 64,
    argon2_time: u32 = 3,
    argon2_par: u32 = 1,
    scrypt_logn: u8 = 15,
    scrypt_r: u32 = 8,
    scrypt_p: u32 = 1,
    pbkdf2_rounds: u32 = 600_000,
    chunk_kib: u32 = 64,
    label: ?[]const u8 = null,
    expect_label: ?[]const u8 = null,
    in_path: ?[]const u8 = null,
    out_path: ?[]const u8 = null,
};

fn hexv(c: u8) !u4 {
    return switch (c) {
        '0'...'9' => @intCast(c - '0'),
        'a'...'f' => @intCast(c - 'a' + 10),
        'A'...'F' => @intCast(c - 'A' + 10),
        else => error.BadHex,
    };
}

fn parseHex(comptime max: usize, s: []const u8, out: *[max]u8) !usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        if (s[i] == ' ') {
            i += 1;
            continue;
        }
        if (i + 1 >= s.len or n >= max) return error.BadHex;
        out[n] = (@as(u8, try hexv(s[i])) << 4) | try hexv(s[i + 1]);
        n += 1;
        i += 2;
    }
    return n;
}

fn nextArg(idx: *usize, av: []const []const u8) []const u8 {
    idx.* += 1;
    if (idx.* >= av.len) die("missing value for a flag", .{});
    return av[idx.*];
}

pub fn main(init: std.process.Init) !void {
    // First thing, before any password or derived key can exist: stop a crash from
    // writing those secrets into a core file on disk.
    suppressCoreDumps();

    const a = init.gpa;
    const io = init.io;

    // Resolve the operator override for the accepted chunk-size cap from the
    // environment (the SDK stays libc-free, so the CLI reads the env and hands the
    // engine the clamped value). Unset/empty/unparseable keeps the default cap.
    fmt.setChunkCapOverride(fmt.chunkCapFrom(init.environ_map.get("DORADO_MAX_CHUNK_BYTES")));

    var arglist: std.ArrayList([]const u8) = .empty;
    defer arglist.deinit(a);
    var it = std.process.Args.Iterator.init(init.minimal.args);
    while (it.next()) |arg| try arglist.append(a, arg);
    const argv = arglist.items;

    // Recognize --help/-h and --version before anything is treated as a
    // subcommand, so `dorado --help` (with no subcommand) prints help and
    // `dorado --version` prints the version, matching the Rust/Go CLIs.
    for (argv[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) printHelp(io);
        if (std.mem.eql(u8, arg, "--version")) printVersion(io);
    }

    if (argv.len < 2) die("usage: dorado <encrypt|decrypt|inspect> [flags]", .{});

    var args = Args{ .command = argv[1] };
    var i: usize = 2;
    while (i < argv.len) : (i += 1) {
        const arg = argv[i];
        if (std.mem.eql(u8, arg, "--key")) {
            args.key = nextArg(&i, argv);
        } else if (std.mem.eql(u8, arg, "--key-file")) {
            args.key_file = nextArg(&i, argv);
        } else if (std.mem.eql(u8, arg, "--iv")) {
            args.iv = nextArg(&i, argv);
        } else if (std.mem.eql(u8, arg, "--tweak")) {
            args.tweak = nextArg(&i, argv);
        } else if (std.mem.eql(u8, arg, "--password")) {
            args.password = true;
        } else if (std.mem.eql(u8, arg, "--password-stdin")) {
            args.password_stdin = true;
        } else if (std.mem.eql(u8, arg, "--unauthenticated")) {
            args.unauthenticated = true;
        } else if (std.mem.eql(u8, arg, "--variant")) {
            args.variant = nextArg(&i, argv);
        } else if (std.mem.eql(u8, arg, "--kdf")) {
            args.kdf = nextArg(&i, argv);
        } else if (std.mem.eql(u8, arg, "--mac")) {
            args.mac = nextArg(&i, argv);
        } else if (std.mem.eql(u8, arg, "--argon2-mem-mib")) {
            args.argon2_mem = try std.fmt.parseInt(u32, nextArg(&i, argv), 10);
        } else if (std.mem.eql(u8, arg, "--argon2-time")) {
            args.argon2_time = try std.fmt.parseInt(u32, nextArg(&i, argv), 10);
        } else if (std.mem.eql(u8, arg, "--argon2-par")) {
            args.argon2_par = try std.fmt.parseInt(u32, nextArg(&i, argv), 10);
        } else if (std.mem.eql(u8, arg, "--scrypt-logn")) {
            args.scrypt_logn = try std.fmt.parseInt(u8, nextArg(&i, argv), 10);
        } else if (std.mem.eql(u8, arg, "--scrypt-r")) {
            args.scrypt_r = try std.fmt.parseInt(u32, nextArg(&i, argv), 10);
        } else if (std.mem.eql(u8, arg, "--scrypt-p")) {
            args.scrypt_p = try std.fmt.parseInt(u32, nextArg(&i, argv), 10);
        } else if (std.mem.eql(u8, arg, "--pbkdf2-rounds")) {
            args.pbkdf2_rounds = try std.fmt.parseInt(u32, nextArg(&i, argv), 10);
        } else if (std.mem.eql(u8, arg, "--chunk-kib")) {
            args.chunk_kib = try std.fmt.parseInt(u32, nextArg(&i, argv), 10);
        } else if (std.mem.eql(u8, arg, "--label")) {
            args.label = nextArg(&i, argv);
        } else if (std.mem.eql(u8, arg, "--expect-label")) {
            args.expect_label = nextArg(&i, argv);
        } else if (std.mem.eql(u8, arg, "--in")) {
            args.in_path = nextArg(&i, argv);
        } else if (std.mem.eql(u8, arg, "--out")) {
            args.out_path = nextArg(&i, argv);
        } else {
            die("unknown flag {s}", .{arg});
        }
    }

    const cwd = std.Io.Dir.cwd();
    var in_file = if (args.in_path) |p|
        cwd.openFile(io, p, .{}) catch die("cannot open input", .{})
    else
        std.Io.File.stdin();
    defer if (args.in_path != null) in_file.close(io);
    var out_file = if (args.out_path) |p|
        cwd.createFile(io, p, .{}) catch die("cannot open output", .{})
    else
        std.Io.File.stdout();
    defer if (args.out_path != null) out_file.close(io);

    var rbuf: [64 * 1024]u8 = undefined;
    var wbuf: [64 * 1024]u8 = undefined;
    var file_reader = in_file.reader(io, &rbuf);
    var file_writer = out_file.writer(io, &wbuf);
    var ra = ReaderAdapter{ .r = &file_reader.interface };
    var wa = WriterAdapter{ .w = &file_writer.interface };

    if (std.mem.eql(u8, args.command, "inspect")) {
        var info: engine.ContainerInfo = undefined;
        engine.inspectStream(ra.iface(), &info) catch |e| die("{s}", .{@errorName(e)});
        try printInfo(&info, &file_writer.interface);
    } else if (std.mem.eql(u8, args.command, "encrypt") or std.mem.eql(u8, args.command, "decrypt")) {
        const enc = std.mem.eql(u8, args.command, "encrypt");
        try crypt(a, io, &args, enc, ra.iface(), wa.iface());
    } else {
        die("usage: dorado <encrypt|decrypt|inspect> [flags]", .{});
    }
    file_writer.interface.flush() catch die("write error", .{});
}

fn crypt(a: std.mem.Allocator, io: std.Io, args: *const Args, enc: bool, r: engine.Reader, w: engine.Writer) !void {
    const creds = @as(u8, @intFromBool(args.key != null)) + @intFromBool(args.key_file != null) +
        @intFromBool(args.password) + @intFromBool(args.password_stdin);
    if (creds != 1) die("provide exactly one of --key, --key-file, --password, --password-stdin", .{});

    var tweak_buf: [16]u8 = undefined;
    if ((parseHex(16, args.tweak, &tweak_buf) catch 0) != 16) die("--tweak must be 16 bytes of hex", .{});

    if (args.key != null or args.key_file != null) {
        var key_hex_buf: [512]u8 = undefined;
        const key_hex = if (args.key) |k| k else blk: {
            const data = std.Io.Dir.cwd().readFileAlloc(io, args.key_file.?, a, .limited(512)) catch die("cannot read key file", .{});
            defer a.free(data);
            @memcpy(key_hex_buf[0..data.len], data);
            break :blk key_hex_buf[0..data.len];
        };
        var key: [128]u8 = undefined;
        const key_len = parseHex(128, key_hex, &key) catch die("invalid key hex", .{});
        const variant = fmt.Variant.fromCode(switch (key_len) {
            32 => 0,
            64 => 1,
            128 => 2,
            else => die("key must be 32, 64, or 128 bytes", .{}),
        }).?;
        if (args.iv == null) die("--iv is required with --key/--key-file", .{});
        var iv: [128]u8 = undefined;
        const iv_len = parseHex(128, args.iv.?, &iv) catch die("invalid iv hex", .{});
        if (iv_len != variant.keyLen()) die("--iv length must match the variant block size", .{});
        if (args.unauthenticated) {
            // The explicit opt-out: bare CTR, symmetric, no tamper detection.
            engine.rawCtrStream(variant, key[0..key_len], &tweak_buf, iv[0..iv_len], a, r, w) catch |e| die("{s}", .{@errorName(e)});
            return;
        }
        // The default: encrypt-then-MAC over the caller's key (the raw
        // authenticated construction), honoring --mac and --chunk-kib.
        const mac_id = macOf(args.mac);
        const chunk_size = args.chunk_kib * 1024;
        if (enc) {
            engine.encryptRawAuthenticatedStream(variant, key[0..key_len], &tweak_buf, iv[0..iv_len], mac_id, chunk_size, a, r, w) catch |e| die("{s}", .{@errorName(e)});
        } else {
            engine.decryptRawAuthenticatedStream(variant, key[0..key_len], &tweak_buf, iv[0..iv_len], mac_id, chunk_size, a, r, w) catch |e| die("{s}", .{@errorName(e)});
        }
        return;
    }

    if (args.iv != null) die("--iv is not used in password mode; the IV is generated and stored", .{});
    if (args.unauthenticated) die("--unauthenticated is not used in password mode, which is always authenticated", .{});
    if (args.password_stdin and args.in_path == null) die("with --password-stdin, pass the data via --in", .{});

    // Hold the password in a page-aligned, mlock'd buffer (kept out of swap), wiped
    // and unlocked on exit. page_allocator returns whole, page-aligned pages.
    const pw_buf = std.heap.page_allocator.alloc(u8, std.heap.pageSize()) catch die("out of memory", .{});
    defer {
        std.crypto.secureZero(u8, pw_buf);
        _ = munlock(pw_buf.ptr, pw_buf.len);
        std.heap.page_allocator.free(pw_buf);
    }
    _ = mlock(pw_buf.ptr, pw_buf.len); // best-effort; wiping still happens on free
    const password = readPassword(io, args, pw_buf);

    if (enc) {
        var opts = engine.Options{
            .variant = variantOf(args.variant),
            .mac = macOf(args.mac),
            .tweak = tweak_buf,
            .chunk_size = args.chunk_kib * 1024,
            .label = if (args.label) |l| l else "",
        };
        opts.kdf = kdfOf(args);
        engine.encryptStream(a, io, password, opts, r, w) catch |e| die("{s}", .{@errorName(e)});
    } else {
        const expect: ?[]const u8 = if (args.expect_label) |l| l else null;
        engine.decryptStream(a, io, password, expect, r, w) catch |e| die("{s}", .{@errorName(e)});
    }
}

fn readPassword(io: std.Io, args: *const Args, buf: []u8) []const u8 {
    if (!args.password_stdin) std.debug.print("Password: ", .{});
    var stdin = std.Io.File.stdin();
    var rbuf: [1024]u8 = undefined;
    var fr = stdin.reader(io, &rbuf);
    const line = fr.interface.takeDelimiterExclusive('\n') catch "";
    var n = @min(line.len, buf.len);
    while (n > 0 and (line[n - 1] == '\r')) n -= 1;
    @memcpy(buf[0..n], line[0..n]);
    if (!args.password_stdin and n == 0) die("password must not be empty", .{});
    return buf[0..n];
}

fn variantOf(s: []const u8) fmt.Variant {
    if (std.mem.eql(u8, s, "256")) return .t256;
    if (std.mem.eql(u8, s, "512")) return .t512;
    if (std.mem.eql(u8, s, "1024")) return .t1024;
    die("unknown --variant {s}", .{s});
}

fn macOf(s: []const u8) fmt.Mac {
    if (std.mem.eql(u8, s, "skein")) return .skein;
    if (std.mem.eql(u8, s, "hmac-sha256")) return .hmac;
    if (std.mem.eql(u8, s, "blake3")) return .blake3;
    die("unknown --mac {s}", .{s});
}

fn kdfOf(args: *const Args) fmt.Kdf {
    if (std.mem.eql(u8, args.kdf, "argon2id")) return fmt.Kdf.mkArgon2id(args.argon2_mem * 1024, args.argon2_time, args.argon2_par);
    if (std.mem.eql(u8, args.kdf, "scrypt")) return fmt.Kdf.mkScrypt(args.scrypt_logn, args.scrypt_r, args.scrypt_p);
    if (std.mem.eql(u8, args.kdf, "pbkdf2")) return fmt.Kdf.mkPbkdf2(args.pbkdf2_rounds);
    die("unknown --kdf {s}", .{args.kdf});
}

fn printInfo(info: *const engine.ContainerInfo, w: *std.Io.Writer) !void {
    const vn = switch (info.variant) {
        .t256 => "Threefish-256",
        .t512 => "Threefish-512",
        .t1024 => "Threefish-1024",
    };
    const mn = switch (info.mac) {
        .skein => "Skein-512",
        .hmac => "HMAC-SHA256",
        .blake3 => "BLAKE3 (keyed)",
    };
    try w.print("format:   dorado password container (DRDO v{d})\n", .{info.version});
    try w.print("variant:  {s}\n", .{vn});
    switch (info.kdf) {
        .argon2id => |x| try w.print("kdf:      Argon2id (memory {d} KiB, iterations {d}, lanes {d})\n", .{ x.m_cost, x.t_cost, x.p_cost }),
        .scrypt => |x| try w.print("kdf:      scrypt (log2(N) {d}, r {d}, p {d})\n", .{ x.log_n, x.r, x.p }),
        .pbkdf2 => |x| try w.print("kdf:      PBKDF2-HMAC-SHA256 (rounds {d})\n", .{x.rounds}),
    }
    try w.print("mac:      {s}\n", .{mn});
    try w.print("chunk:    {d} bytes\n", .{info.chunk_size});
    try w.print("salt:     {d} bytes\n", .{info.salt_len});
    try w.print("tweak:    {x}\n", .{info.tweak});
    if (info.label_len > 0) {
        try w.print("label:    {s}\n", .{info.labelSlice()});
    } else {
        try w.print("label:    (none)\n", .{});
    }
}
