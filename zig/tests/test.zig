//! Test suite for the Zig port: primitive KATs (official + Rust-baked vectors), the
//! construction's round-trips and security properties, and cross-compat fixtures
//! produced by the Rust reference (embedded with @embedFile). Run with `zig build test`.

const std = @import("std");
const testing = std.testing;
const dorado = @import("dorado");
const threefish = dorado.threefish;
const skein = dorado.skein;
const blake3 = dorado.blake3;
const fmt = dorado.format;
const engine = dorado.engine;

fn hexEql(got: []const u8, expect_hex: []const u8) !void {
    var buf: [256]u8 = undefined;
    const hex = std.fmt.bufPrint(&buf, "{x}", .{got}) catch unreachable;
    try testing.expectEqualStrings(expect_hex, hex);
}

fn seq(comptime n: usize) [n]u8 {
    var b: [n]u8 = undefined;
    for (0..n) |i| b[i] = @intCast(i & 0xff);
    return b;
}

test "threefish-256 KAT" {
    var key: [32]u8 = undefined;
    var tw: [16]u8 = undefined;
    var pt: [32]u8 = undefined;
    for (0..32) |i| {
        key[i] = @intCast(0x10 + i);
        pt[i] = @intCast(0xff - i);
    }
    for (0..16) |i| tw[i] = @intCast(i);
    const c = threefish.Threefish.init(.t256, &key, &tw);
    var ct: [32]u8 = undefined;
    c.encryptBlock(&ct, &pt);
    try hexEql(&ct, "e0d091ff0eea8fdfc98192e62ed80ad59d865d08588df476657056b5955e97df");
    var back: [32]u8 = undefined;
    c.decryptBlock(&back, &ct);
    try testing.expectEqualSlices(u8, &pt, &back);
}

test "threefish CTR round-trip" {
    const key = seq(32);
    const tw = [_]u8{0} ** 16;
    const iv = seq(32);
    const plain = "any length, not just one block -- CTR handles it";
    var buf: [48]u8 = undefined;
    @memcpy(&buf, plain);
    var c = threefish.Threefish.init(.t256, &key, &tw);
    var ctr = c.newCtr(&iv);
    ctr.apply(&buf);
    try testing.expect(!std.mem.eql(u8, &buf, plain));
    var ctr2 = c.newCtr(&iv);
    ctr2.apply(&buf);
    try testing.expectEqualStrings(plain, &buf);
}

test "skein-512 KATs" {
    var o: [64]u8 = undefined;
    skein.hash(64, "", o[0..64]);
    try hexEql(o[0..64], "bc5b4c50925519c290cc634277ae3d6257212395cba733bbad37a4af0fa06af4" ++
        "1fca7903d06564fea7a2d3730dbdb80c1f85562dfcc070334ea4d1d9e72cba7a");
    skein.hash(32, "abc", o[0..32]);
    try hexEql(o[0..32], "0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527");
    const s500 = seq(500);
    skein.hash(32, &s500, o[0..32]);
    try hexEql(o[0..32], "15096f2f503dce8eab3ab3ac80d840dafdd8001ca1737fab69b717475b4abdaf");
    var key = [_]u8{0x9c} ** 32;
    skein.mac(&key, 32, "authenticate me", o[0..32]);
    try hexEql(o[0..32], "8b0865bcabf2dec950b2178b5127e88914d039a0681339e5d10e06d95bad12b3");
}

test "blake3 KATs" {
    var o: [32]u8 = undefined;
    blake3.hash(32, "", &o);
    try hexEql(&o, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    const b3000 = seq(3000);
    blake3.hash(32, &b3000, &o);
    try hexEql(&o, "6c943946a70794f2e14c785d5ee88d300d5f9b91d1b4ef88302974ac4b069052");
    var key = [_]u8{0x9c} ** 32;
    blake3.keyedMac(&key, "authenticate me", &o);
    try hexEql(&o, "e8a84781007d67df2b0de8cf1d0c48b0fee97a0f9744ba5b325c1aac2d670a08");
}

const TestEnv = struct {
    threaded: std.Io.Threaded,
    fn io(self: *TestEnv) std.Io {
        return self.threaded.io();
    }
};

test "engine round-trip every variant/kdf/mac" {
    const a = testing.allocator;
    var threaded = std.Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const pw = "correct horse battery staple";
    const pt = "the quick brown fox jumps over the lazy dog";
    const variants = [_]fmt.Variant{ .t256, .t512, .t1024 };
    const macs = [_]fmt.Mac{ .skein, .hmac, .blake3 };
    const kdfs = [_]fmt.Kdf{ fmt.Kdf.mkArgon2id(8 * 1024, 1, 1), fmt.Kdf.mkScrypt(14, 8, 1), fmt.Kdf.mkPbkdf2(20000) };
    for (variants) |v| for (kdfs) |k| for (macs) |m| {
        const opts = engine.Options{ .variant = v, .kdf = k, .mac = m };
        const ct = try engine.encrypt(a, io, pw, opts, pt);
        defer a.free(ct);
        const back = try engine.decrypt(a, io, pw, null, ct);
        defer a.free(back);
        try testing.expectEqualStrings(pt, back);
    };
}

test "engine empty + multi-chunk" {
    const a = testing.allocator;
    var threaded = std.Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const opts = engine.Options{ .kdf = fmt.Kdf.mkPbkdf2(20000), .mac = .skein };
    const ct0 = try engine.encrypt(a, io, "pw", opts, "");
    defer a.free(ct0);
    const back0 = try engine.decrypt(a, io, "pw", null, ct0);
    defer a.free(back0);
    try testing.expectEqual(@as(usize, 0), back0.len);

    var big: [5000]u8 = undefined;
    for (0..5000) |i| big[i] = @intCast((i * 7) & 0xff);
    var opts2 = opts;
    opts2.chunk_size = 128;
    const ct = try engine.encrypt(a, io, "pw", opts2, &big);
    defer a.free(ct);
    const back = try engine.decrypt(a, io, "pw", null, ct);
    defer a.free(back);
    try testing.expectEqualSlices(u8, &big, back);
}

test "engine rejects wrong password / tampering / truncation / bad magic" {
    const a = testing.allocator;
    var threaded = std.Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    const opts = engine.Options{ .kdf = fmt.Kdf.mkPbkdf2(20000), .mac = .skein };
    const ct = try engine.encrypt(a, io, "pw", opts, "secret");
    defer a.free(ct);

    try testing.expectError(engine.Error.AuthFailed, engine.decrypt(a, io, "wrong", null, ct));

    const tampered = try a.dupe(u8, ct);
    defer a.free(tampered);
    tampered[tampered.len - 1] ^= 1;
    try testing.expectError(engine.Error.AuthFailed, engine.decrypt(a, io, "pw", null, tampered));

    try testing.expectError(engine.Error.Truncated, engine.decrypt(a, io, "pw", null, ct[0 .. ct.len - 8]));

    var info: engine.ContainerInfo = undefined;
    try testing.expectError(engine.Error.BadMagic, engine.inspect("XXXX\x00\x00\x00\x00", &info));
}

test "engine label binding + hostile kdf cost" {
    const a = testing.allocator;
    var threaded = std.Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    var opts = engine.Options{ .kdf = fmt.Kdf.mkPbkdf2(20000), .mac = .skein };
    opts.label = "demo-context";
    const ct = try engine.encrypt(a, io, "pw", opts, "payload");
    defer a.free(ct);
    const ok = try engine.decrypt(a, io, "pw", "demo-context", ct);
    defer a.free(ok);
    try testing.expectEqualStrings("payload", ok);
    const noexp = try engine.decrypt(a, io, "pw", null, ct);
    defer a.free(noexp);
    try testing.expectEqualStrings("payload", noexp);
    try testing.expectError(engine.Error.BadContainer, engine.decrypt(a, io, "pw", "other", ct));

    var info: engine.ContainerInfo = undefined;
    try engine.inspect(ct, &info);
    try testing.expectEqualStrings("demo-context", info.labelSlice());

    // Patch header m_cost (offset 7) to 2^31, which validate() must reject.
    const argon = engine.Options{ .kdf = fmt.Kdf.mkArgon2id(8 * 1024, 1, 1), .mac = .skein };
    const act = try engine.encrypt(a, io, "pw", argon, "x");
    defer a.free(act);
    const patched = try a.dupe(u8, act);
    defer a.free(patched);
    patched[7] = 0x80;
    patched[8] = 0;
    patched[9] = 0;
    patched[10] = 0;
    try testing.expectError(engine.Error.HostileCost, engine.decrypt(a, io, "pw", null, patched));
}

// Cross-compat: decrypt .mahi fixtures produced by the Rust reference (embedded).
test "chunkCapFrom policy (effective chunk-size cap)" {
    // null/empty -> default
    try testing.expectEqual(fmt.DEFAULT_MAX_CHUNK_BYTES, fmt.chunkCapFrom(null));
    try testing.expectEqual(fmt.DEFAULT_MAX_CHUNK_BYTES, fmt.chunkCapFrom(""));
    // unparseable -> default
    try testing.expectEqual(fmt.DEFAULT_MAX_CHUNK_BYTES, fmt.chunkCapFrom("xyz"));
    try testing.expectEqual(fmt.DEFAULT_MAX_CHUNK_BYTES, fmt.chunkCapFrom("-1"));
    // a plain value passes through
    try testing.expectEqual(@as(u32, 1024), fmt.chunkCapFrom("1024"));
    // "0" clamps up to 1
    try testing.expectEqual(@as(u32, 1), fmt.chunkCapFrom("0"));
    // above 1 GiB clamps to the hard ceiling
    try testing.expectEqual(fmt.MAX_CHUNK_BYTES, fmt.chunkCapFrom("2147483648"));
}

const fixtures = .{
    .{ @embedFile("fixtures/argon_skein_256.mahi"), "rust argon+skein+256" },
    .{ @embedFile("fixtures/scrypt_hmac_512.mahi"), "rust scrypt+hmac+512" },
    .{ @embedFile("fixtures/pbkdf2_blake3_1024.mahi"), "rust pbkdf2+blake3+1024" },
    .{ @embedFile("fixtures/labeled.mahi"), "rust labeled payload" },
};

test "cross-compat with Rust fixtures" {
    const a = testing.allocator;
    var threaded = std.Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();
    inline for (fixtures) |fx| {
        const data: []const u8 = fx[0];
        const back = try engine.decrypt(a, io, "pw-cross", null, data);
        defer a.free(back);
        try testing.expectEqualStrings(fx[1], back);
    }
    const mc = try engine.decrypt(a, io, "pw-cross", null, @embedFile("fixtures/multichunk.mahi"));
    defer a.free(mc);
    try testing.expectEqual(@as(usize, 5000), mc.len);
    for (mc) |b| try testing.expectEqual(@as(u8, 'x'), b);
}

comptime {
    _ = TestEnv;
}
