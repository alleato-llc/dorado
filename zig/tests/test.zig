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
const kdf = dorado.kdf;
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

// ---------------------------------------------------------------------------
// Key-based derivation (deriveFromKey / deriveFromKeyWith): the six
// cross-language known-answer vectors from docs/fixtures/derive-from-key.md
// (generated from and verified against the Rust reference), plus the
// determinism and domain-separation properties. Library API only; nothing here
// touches the on-disk container format.
// ---------------------------------------------------------------------------

test "derive-from-key: six KAT vectors match byte-for-byte" {
    const key32 = seq(32); // 000102...1f
    const key16 = [_]u8{0xa5} ** 16;
    var out32: [32]u8 = undefined;
    var out64: [64]u8 = undefined;

    // skein_32key_enc_32out
    try kdf.deriveFromKeyWith(.skein512, &key32, "dorado/fixture/enc", &out32);
    try hexEql(&out32, "b638c503342dbd51bdfa8906b1cc6b18d7e54252b95e460c522ab3cd939802c6");
    // The default, PRF-less form is defined as the Skein-512 case and must
    // match the same vector byte-for-byte.
    kdf.deriveFromKey(&key32, "dorado/fixture/enc", &out32);
    try hexEql(&out32, "b638c503342dbd51bdfa8906b1cc6b18d7e54252b95e460c522ab3cd939802c6");

    // skein_32key_mac_64out
    try kdf.deriveFromKeyWith(.skein512, &key32, "dorado/fixture/mac", &out64);
    try hexEql(&out64, "6ae3f6f7518e9a4c8a7be8269deb848186beb64b5b43f0bafef81bce4b27d40e" ++
        "f227e2064b941069cc6225cad0a39fcc22aba08fb87f3ba8aacdf4b70b100da6");

    // skein_16key_enc_32out (the Skein-512 PRF accepts a key of any length)
    try kdf.deriveFromKeyWith(.skein512, &key16, "dorado/fixture/enc", &out32);
    try hexEql(&out32, "3990e038c7235e62480afe99712203225194afb93910df4101447098e630d0e4");

    // skein_32key_empty_domain_32out (the DRDOkdrv prefix alone is the message)
    try kdf.deriveFromKeyWith(.skein512, &key32, "", &out32);
    try hexEql(&out32, "5bba4214745b3932c1fc620c660b60a4058613ff2bd9d80224d472cd810f7a99");

    // blake3_32key_enc_32out
    try kdf.deriveFromKeyWith(.blake3, &key32, "dorado/fixture/enc", &out32);
    try hexEql(&out32, "8266bd0cfb0d73715aa841fe008c311a44d6b36e0aa01b94f13a90783fe62e1d");

    // blake3_32key_mac_64out
    try kdf.deriveFromKeyWith(.blake3, &key32, "dorado/fixture/mac", &out64);
    try hexEql(&out64, "ea38a1780192707518d15003262a66c245680a579762a7d863cc33078f2f6eaa" ++
        "9a5086f70d00eb7c6cd12fdc7872e5a2023e63c28087631ce835d7e9c7264290");
}

test "derive-from-key: deterministic and domain-separated" {
    const master = [_]u8{0x42} ** 32;
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    kdf.deriveFromKey(&master, "myapp/index", &a);
    kdf.deriveFromKey(&master, "myapp/index", &b);
    try testing.expectEqualSlices(u8, &a, &b); // same key + domain, same bytes

    var c: [32]u8 = undefined;
    kdf.deriveFromKey(&master, "myapp/data", &c);
    try testing.expect(!std.mem.eql(u8, &a, &c)); // different domain, different key

    const other = [_]u8{0x43} ** 32;
    var d: [32]u8 = undefined;
    kdf.deriveFromKey(&other, "myapp/index", &d);
    try testing.expect(!std.mem.eql(u8, &a, &d)); // different master, different key

    // Children reveal nothing about each other or the master: at minimum,
    // none of them may equal the master.
    try testing.expect(!std.mem.eql(u8, &a, &master));
    try testing.expect(!std.mem.eql(u8, &c, &master));
}

test "derive-from-key: output length is bound into Skein, not a truncation" {
    // The 1024-bit variant's raw mode needs 128-byte keys; Skein's output
    // length is free, so longer outputs must work and must not merely
    // prefix-extend shorter ones (the length is part of Skein's config block).
    const master = [_]u8{0x42} ** 32;
    var short: [32]u8 = undefined;
    var long: [128]u8 = undefined;
    kdf.deriveFromKey(&master, "myapp/index", &short);
    kdf.deriveFromKey(&master, "myapp/index", &long);
    try testing.expect(!std.mem.eql(u8, &short, long[0..32]));
}

test "derive-from-key: blake3 PRF is deterministic, domain-separated, and distinct from skein" {
    const master = [_]u8{0x42} ** 32;
    var a: [32]u8 = undefined;
    var b: [32]u8 = undefined;
    try kdf.deriveFromKeyWith(.blake3, &master, "myapp/index", &a);
    try kdf.deriveFromKeyWith(.blake3, &master, "myapp/index", &b);
    try testing.expectEqualSlices(u8, &a, &b);

    var c: [32]u8 = undefined;
    try kdf.deriveFromKeyWith(.blake3, &master, "myapp/data", &c);
    try testing.expect(!std.mem.eql(u8, &a, &c));
    try testing.expect(!std.mem.eql(u8, &a, &master));

    // The two PRFs are independent functions: the same key/domain under Skein
    // and under BLAKE3 must not coincide.
    var sk: [32]u8 = undefined;
    try kdf.deriveFromKeyWith(.skein512, &master, "myapp/index", &sk);
    try testing.expect(!std.mem.eql(u8, &a, &sk));

    // BLAKE3 is an XOF: a shorter output is the prefix of a longer one (unlike
    // Skein, where the length is bound into the hash).
    var long: [128]u8 = undefined;
    try kdf.deriveFromKeyWith(.blake3, &master, "myapp/index", &long);
    try testing.expectEqualSlices(u8, &a, long[0..32]);
}

test "derive-from-key: blake3 PRF rejects a non-32-byte key" {
    var out: [32]u8 = undefined;
    const short_key = [_]u8{0} ** 16;
    try testing.expectError(kdf.Error.BadKeyLength, kdf.deriveFromKeyWith(.blake3, &short_key, "myapp/index", &out));
}

test "kdf validate: zero pbkdf2 rounds are rejected, like an oversized count" {
    try kdf.validate(fmt.Kdf.mkPbkdf2(600_000));
    // Zero rounds would "derive" an all-zero key without error.
    try testing.expectError(kdf.Error.HostileCost, kdf.validate(fmt.Kdf.mkPbkdf2(0)));
    try testing.expectError(kdf.Error.HostileCost, kdf.validate(fmt.Kdf.mkPbkdf2(0xffff_ffff)));
}

// ---------------------------------------------------------------------------
// Raw-key authenticated CTR (encrypt-then-MAC, caller-supplied key): six
// cross-language known-answer vectors from docs/fixtures/raw-authenticated.md
// (generated from and verified against the Rust reference), plus the
// construction's security properties. Bare rawCtrStream (unauthenticated) is
// untouched by this construction and keeps its own coverage above.
// ---------------------------------------------------------------------------

const RawKat = struct {
    name: []const u8,
    variant: fmt.Variant,
    mac: fmt.Mac,
    chunk_size: u32,
    key_hex: []const u8,
    iv_hex: []const u8,
    tweak_hex: []const u8,
    plaintext_hex: []const u8,
    ciphertext_hex: []const u8,
};

const raw_kats = [_]RawKat{
    .{
        .name = "t256_skein_single",
        .variant = .t256,
        .mac = .skein,
        .chunk_size = 65536,
        .key_hex = "1111111111111111111111111111111111111111111111111111111111111111",
        .iv_hex = "0202020202020202020202020202020202020202020202020202020202020202",
        .tweak_hex = "00000000000000000000000000000000",
        .plaintext_hex = "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c616e677561676573",
        .ciphertext_hex = "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b8961a7bb9296d0da601e3aba580a70532ad6b83e8fc1050620de95d5ba50e545621",
    },
    .{
        .name = "t256_hmac_single",
        .variant = .t256,
        .mac = .hmac,
        .chunk_size = 65536,
        .key_hex = "1111111111111111111111111111111111111111111111111111111111111111",
        .iv_hex = "0202020202020202020202020202020202020202020202020202020202020202",
        .tweak_hex = "00000000000000000000000000000000",
        .plaintext_hex = "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c616e677561676573",
        .ciphertext_hex = "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b8968381b4daded95b311377792e768eee91a63e2346b585ac3eda337afd6ed6dfff",
    },
    .{
        .name = "t256_blake3_single",
        .variant = .t256,
        .mac = .blake3,
        .chunk_size = 65536,
        .key_hex = "1111111111111111111111111111111111111111111111111111111111111111",
        .iv_hex = "0202020202020202020202020202020202020202020202020202020202020202",
        .tweak_hex = "00000000000000000000000000000000",
        .plaintext_hex = "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c616e677561676573",
        .ciphertext_hex = "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b896815761a7e9f6762a4a0dd0de969ab2bf00e7d04304b45fb53984b5e29deb9834",
    },
    .{
        .name = "t512_skein_single",
        .variant = .t512,
        .mac = .skein,
        .chunk_size = 65536,
        .key_hex = "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        .iv_hex = "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
        .tweak_hex = "00000000000000000000000000000000",
        .plaintext_hex = "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c616e677561676573",
        .ciphertext_hex = "010000003e9b6cf38a329d996ff458a80a5993a2fbbb8b29237d5561b5a7883b2b47eb06ca7ea842953feb5ebf6aec6b95d17c646a8294b66e6f04a98ffc255ee4e62d44f0b6fa861dc2ea6a8be5fd71b60863900177af52c649ede00952bde11f1394",
    },
    .{
        .name = "t1024_skein_single",
        .variant = .t1024,
        .mac = .skein,
        .chunk_size = 65536,
        .key_hex = "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111",
        .iv_hex = "0202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202",
        .tweak_hex = "00000000000000000000000000000000",
        .plaintext_hex = "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c616e677561676573",
        .ciphertext_hex = "010000003ef55cd4e609b16c109712985cc509501cd194befaa963a620c123816bd9fd494f85cd899f2a52b005a0fb1105fe6706ceb7f937573662a11b14b53c939c8ade26889e72113babe3236093b8855432a67c45888b131be41f72cd890a724f0f",
    },
    .{
        .name = "t256_skein_multichunk",
        .variant = .t256,
        .mac = .skein,
        .chunk_size = 1024,
        .key_hex = "1111111111111111111111111111111111111111111111111111111111111111",
        .iv_hex = "0202020202020202020202020202020202020202020202020202020202020202",
        .tweak_hex = "00000000000000000000000000000000",
        .plaintext_hex = "61206c6f6e676572207061796c6f6164206d65616e7420746f207370616e206d756c7469706c65206f6e652d6b696c6f627974652061757468656e74696361746564206368756e6b7320736f207468652063726f73732d6c616e6775616765206669787475726520616c736f206578657263697365732074686520636f6e74696e756f757320636f756e74657220616e64207065722d6672616d652074616767696e67206163726f7373206368756e6b20626f756e6461726965732c206e6f74206a75737420612073696e676c65206672616d652e20787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878",
        .ciphertext_hex = "0000000400f22a092b48a93449b906d28f4e1d30649ff11c6761b40436f8837cfa9715f834310c46654feabc437288741b5f16b5ff8bab79018d524a3a5bc2f307b486959bdb2b43f608b3a624af1d302506d312ff8c536eee10f553ab87e39697249ea5f92050c9ee832a8c8c2d7e4dffba0d5b3650a65d4ec8ef92c6ec60d2030c334e56e091654db2e1ad8e3cbc921f7092bc34afc8d41226526e31b1da8240da06169ef5643695b82247984b334e4842a34b88789ff0886098e002521245065ba7e1550136a7817ed24f451cc0a1f8c778dbc3febc1e0de9fd4810f7077c85a8ac7dd49b0c34546708ccba6babcc1391a2f0d2d0e44f848f5f8d894f48d2b2f0f8854bb6257179d883d55cf7b21c5c764fb1008f582917a6d54ddd75209c39814a1f0c795fcdcf11fb69fa36bbbdf9d798338cf01a20326fc4c4d9e0ce7d874cd0f6b5bc493dcfaac173f8259f597a1d28c72e92e2b47a7573857e0dd47b1ef6192b97434fdc7572f5ed93c4eee4b0466bed9246a037334cc319ab9d06830edccd3bca5ef2e69769a4d2a57b5d3cde17381ba1d5dee0f828ff67b0b31b1f78d6684a2ef8596c0cf60ba76834ce054fb4f7e524df218c21c2f552f74e445efbbc24c8b29df788c92b0c0a08251583fa6f0dbc187ff8dc11f572160e9f813aa04868a69ca4c0f8b111d5213ef4d7e7be43d34c4db41241764093e1f259ce6430b754aaeeaa5fd010334928380060453213fde390d7d1b36f0f34242b5856df0e13f6bcc351c557c3b4b0fb5db5382bf229818a094b9ad714d0d73ba734da002a4c1fdf9613c25556ed9cb350f1d17a863ddb72a13688f51e7e56f9f6d97fcf1b7f050c4a5f45c0760ae09f19fdccebc47d48cb6a22de0b2327a30f19038b2bf06e69e3229fd9db1b55dad18a30bc67f3b4670a35b9c17884feb94f6c7b1183faadb7c60768c34e098754d59ce4b057249e5a7e0fc37a84925d8582a996e3ff38a3e844711f444a8ad1bbcda549b9d3b3d1f1a1c436cca8bd093056207951372661e6f1d673d04279a7bbb35bccb5bc5b16053506d66c0171417a7428b40e117b21f20d73ffd4a0b4c31a8314fc41415f23ea59fb375e090a1442f3a99b46ffcb2db05ae459912ace292e382feddede89ce478b2f09072e8415442d5208e7be684406bcd8d1daf671471c875e9473d23be31ae5cb4dd59166fca876d33c1bc4354275ac62acc6e797e78c6255fc4aa500776fdd556364c98c0c0bdb00f897bdf6e782a74a65b67539a0b5d2d0d18fb3368d45913b2e1cac5e4b6c6c790c0327b2fd8569c1182a945859c9fed3e0009cf6067ff4910f6fab39d77d8da052a1aec80b115391f717475e9f8ab01ca3a2e7f4ed45e15cb8590c01f6274aae9b75e3852fce44b07f41bfe18777395112bbafbfab1be72df1be7a16e502d3385ff547f083bab16cd43d57f00d8fcce0595e3b57f18b2ca2da0f94f8c42bdc5237a41673617ea43d010000018657d51b2abd9a7809306c46b7c1020a729dd1efddc182b7412e45fae64f45b3e33ad6440f1d827977eb3f5b3e583d718a8c0fb43d4b00d557dc9a7afeef9a361a3a18014fa545baa6a184836a082798c4de40c82b96a5a5cd557fb4a8e15d6d0d5f411e6083b3f2c14b716c7a4d5167e077b1a2ded34f9e30eea332309801843ea53f53bea4f265ee8176a28c08b80f0189d754bef399ebd1c4407432af717dd7b949f8eee02cf4dca067b4b6cd7f50dd53b8bff3e35af9352d0d62b3ccf4d3f5af2eb8ed593200c1826984322967bf1bd6f682ff312690bf64c277bad2ab306931e97e23dd5790127921af7d16617456c585b835117b08621c40dddd38929d0728da224e31dd1d2d5461b2ce6e162f41436c92b5515223aa3f9572ab9ede606fb0c2c94545cc6221179aa6c11508e2dc6f1be11d8c82d051609ca26b397fffdbfd26d76301e1ecc03ab9699df7863eeee1a9bdd861c71319b3195e32215a56ada80234a28b8c31376c6846df120d9f0eb0979b618dd62b78e2fb886e7412cd9137451c75ace33797024dadf2784b969e1c56a81088dd5ac19c8a6061d2c9519c4309170d8192",
    },
};

fn hexAlloc(a: std.mem.Allocator, hexs: []const u8) ![]u8 {
    const buf = try a.alloc(u8, hexs.len / 2);
    return std.fmt.hexToBytes(buf, hexs) catch unreachable;
}

test "raw authenticated: six KAT vectors match byte-for-byte, both directions" {
    const a = testing.allocator;
    for (raw_kats) |v| {
        const key = try hexAlloc(a, v.key_hex);
        defer a.free(key);
        const iv = try hexAlloc(a, v.iv_hex);
        defer a.free(iv);
        const tweak = try hexAlloc(a, v.tweak_hex);
        defer a.free(tweak);
        const pt = try hexAlloc(a, v.plaintext_hex);
        defer a.free(pt);
        const ct = try hexAlloc(a, v.ciphertext_hex);
        defer a.free(ct);

        const got_ct = try engine.encryptRawAuthenticated(a, v.variant, key, tweak, iv, v.mac, v.chunk_size, pt);
        defer a.free(got_ct);
        testing.expectEqualSlices(u8, ct, got_ct) catch |err| {
            std.debug.print("KAT {s}: encrypt mismatch\n", .{v.name});
            return err;
        };

        const got_pt = try engine.decryptRawAuthenticated(a, v.variant, key, tweak, iv, v.mac, v.chunk_size, ct);
        defer a.free(got_pt);
        testing.expectEqualSlices(u8, pt, got_pt) catch |err| {
            std.debug.print("KAT {s}: decrypt mismatch\n", .{v.name});
            return err;
        };
    }
}

test "raw authenticated: round-trip with an arbitrary key/iv (non-t256 variant)" {
    const a = testing.allocator;
    var key: [64]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast((i * 37 + 11) & 0xff);
    var iv: [64]u8 = undefined;
    for (&iv, 0..) |*b, i| b.* = @intCast((i * 5 + 3) & 0xff);
    const tweak = [_]u8{0xab} ** 16;
    const pt = "arbitrary plaintext for a non-256 variant round-trip, long enough to span more than one 64-byte block of keystream.";
    const ct = try engine.encryptRawAuthenticated(a, .t512, &key, &tweak, &iv, .hmac, 4096, pt);
    defer a.free(ct);
    const back = try engine.decryptRawAuthenticated(a, .t512, &key, &tweak, &iv, .hmac, 4096, ct);
    defer a.free(back);
    try testing.expectEqualStrings(pt, back);
}

test "raw authenticated: tamper detection (body and tag) is rejected, never partial output" {
    const a = testing.allocator;
    const v = raw_kats[0];
    const key = try hexAlloc(a, v.key_hex);
    defer a.free(key);
    const iv = try hexAlloc(a, v.iv_hex);
    defer a.free(iv);
    const tweak = try hexAlloc(a, v.tweak_hex);
    defer a.free(tweak);
    const ct = try hexAlloc(a, v.ciphertext_hex);
    defer a.free(ct);

    // Flip a byte in the ciphertext body.
    const tampered_body = try a.dupe(u8, ct);
    defer a.free(tampered_body);
    tampered_body[10] ^= 0x01;
    try testing.expectError(engine.Error.AuthFailed, engine.decryptRawAuthenticated(a, v.variant, key, tweak, iv, v.mac, v.chunk_size, tampered_body));

    // Flip a byte in the trailing tag.
    const tampered_tag = try a.dupe(u8, ct);
    defer a.free(tampered_tag);
    tampered_tag[tampered_tag.len - 1] ^= 0x01;
    try testing.expectError(engine.Error.AuthFailed, engine.decryptRawAuthenticated(a, v.variant, key, tweak, iv, v.mac, v.chunk_size, tampered_tag));
}

test "raw authenticated: wrong key is rejected" {
    const a = testing.allocator;
    const v = raw_kats[0];
    const iv = try hexAlloc(a, v.iv_hex);
    defer a.free(iv);
    const tweak = try hexAlloc(a, v.tweak_hex);
    defer a.free(tweak);
    const ct = try hexAlloc(a, v.ciphertext_hex);
    defer a.free(ct);
    // Same length as the KAT's key (all 0x11), different content.
    var wrong_key: [32]u8 = undefined;
    @memset(&wrong_key, 0x22);
    try testing.expectError(engine.Error.AuthFailed, engine.decryptRawAuthenticated(a, v.variant, &wrong_key, tweak, iv, v.mac, v.chunk_size, ct));
}

test "raw authenticated: mismatched tweak or IV is rejected (bound into frame 0's AAD)" {
    const a = testing.allocator;
    const v = raw_kats[0];
    const key = try hexAlloc(a, v.key_hex);
    defer a.free(key);
    const iv = try hexAlloc(a, v.iv_hex);
    defer a.free(iv);
    const tweak = try hexAlloc(a, v.tweak_hex);
    defer a.free(tweak);
    const ct = try hexAlloc(a, v.ciphertext_hex);
    defer a.free(ct);

    var wrong_tweak: [16]u8 = undefined;
    @memcpy(&wrong_tweak, tweak);
    wrong_tweak[0] ^= 0x01;
    try testing.expectError(engine.Error.AuthFailed, engine.decryptRawAuthenticated(a, v.variant, key, &wrong_tweak, iv, v.mac, v.chunk_size, ct));

    const wrong_iv = try a.dupe(u8, iv);
    defer a.free(wrong_iv);
    wrong_iv[0] ^= 0x01;
    try testing.expectError(engine.Error.AuthFailed, engine.decryptRawAuthenticated(a, v.variant, key, tweak, wrong_iv, v.mac, v.chunk_size, ct));
}

test "raw authenticated: every MAC option round-trips and rejects tampering" {
    const a = testing.allocator;
    const macs = [_]fmt.Mac{ .skein, .hmac, .blake3 };
    var key: [32]u8 = undefined;
    for (&key, 0..) |*b, i| b.* = @intCast((i * 13 + 7) & 0xff);
    var iv: [32]u8 = undefined;
    for (&iv, 0..) |*b, i| b.* = @intCast((i * 29 + 1) & 0xff);
    const tweak = [_]u8{0x5a} ** 16;
    const pt = "every mac option must round-trip and reject tampering";
    for (macs) |m| {
        const ct = try engine.encryptRawAuthenticated(a, .t256, &key, &tweak, &iv, m, 4096, pt);
        defer a.free(ct);
        const back = try engine.decryptRawAuthenticated(a, .t256, &key, &tweak, &iv, m, 4096, ct);
        defer a.free(back);
        try testing.expectEqualStrings(pt, back);

        const tampered = try a.dupe(u8, ct);
        defer a.free(tampered);
        tampered[tampered.len - 1] ^= 0x01;
        try testing.expectError(engine.Error.AuthFailed, engine.decryptRawAuthenticated(a, .t256, &key, &tweak, &iv, m, 4096, tampered));
    }
}

// Accept only the engine's declared errors; anything else (or a panic / UB trap
// under ReleaseSafe) fails the test. A panic would abort before we get here, which
// is exactly the failure we are hunting for.
fn assertEngineErrorOrOk(result: engine.Error![]u8, a: std.mem.Allocator) !void {
    if (result) |buf| {
        a.free(buf);
    } else |err| switch (err) {
        // The full closed set the decrypt path is allowed to surface.
        error.LabelTooLong,
        error.InvalidChunkSize,
        error.BadContainer,
        error.AuthFailed,
        error.Truncated,
        error.WriteFailed,
        error.OutOfMemory,
        error.Rng,
        error.KdfFailed,
        error.HostileCost,
        error.BadKeyLength,
        error.BadMagic,
        error.UnsupportedVersion,
        error.UnknownVariant,
        error.UnknownKdf,
        error.UnknownPrf,
        error.UnknownMac,
        => {},
    }
}

// Deterministic randomized "smash" test for the decrypt entrypoint. It feeds many
// pseudo-random, truncated, and bit-mutated byte slices to engine.decrypt and asserts
// that every call either succeeds or returns one of the engine's errors, and never
// panics or triggers undefined behavior. Because the build defaults to ReleaseSafe and
// tests keep safety checks on, any out-of-bounds or overflow would trap and fail here
// rather than be silently accepted. Seeded for reproducibility.
test "smash: decrypt never panics on hostile input" {
    const a = testing.allocator;
    var threaded = std.Io.Threaded.init(a, .{});
    defer threaded.deinit();
    const io = threaded.io();

    var prng = std.Random.DefaultPrng.init(0x5EED_D0_8ADA);
    const rand = prng.random();

    // A cheap-KDF base container so mutating its bytes stays fast: pbkdf2 with low
    // rounds. Mutations that flip the header into an expensive-but-valid KDF are
    // statistically rare (a random u32 cost almost always exceeds validate()'s cap
    // and is rejected as HostileCost).
    const opts = engine.Options{ .kdf = fmt.Kdf.mkPbkdf2(1000), .mac = .skein };
    const base = try engine.encrypt(a, io, "pw", opts, "the smash test plaintext payload");
    defer a.free(base);

    const ITERS = 3000;

    // 1) Pure pseudo-random slices of varied lengths (most rejected early at the
    //    magic / header parse, but exercises the length and bounds logic).
    {
        var buf: [512]u8 = undefined;
        var i: usize = 0;
        while (i < ITERS) : (i += 1) {
            const len = rand.intRangeAtMost(usize, 0, buf.len);
            rand.bytes(buf[0..len]);
            // Half the time, start from a valid magic so we get deeper into the parser.
            if (rand.boolean() and len >= 4) @memcpy(buf[0..4], fmt.MAGIC);
            try assertEngineErrorOrOk(engine.decrypt(a, io, "pw", null, buf[0..len]), a);
        }
    }

    // 2) Truncations of a real container at every prefix length.
    {
        var cut: usize = 0;
        while (cut <= base.len) : (cut += 1) {
            try assertEngineErrorOrOk(engine.decrypt(a, io, "pw", null, base[0..cut]), a);
        }
    }

    // 3) Single- and multi-byte mutations of a real container, with an occasional
    //    random expected_label to exercise the label-binding branch too.
    {
        const scratch = try a.alloc(u8, base.len);
        defer a.free(scratch);
        var i: usize = 0;
        while (i < ITERS) : (i += 1) {
            @memcpy(scratch, base);
            const flips = rand.intRangeAtMost(usize, 1, 6);
            var f: usize = 0;
            while (f < flips) : (f += 1) {
                const pos = rand.intRangeLessThan(usize, 0, scratch.len);
                scratch[pos] ^= rand.int(u8);
            }
            const label: ?[]const u8 = if (rand.boolean()) "ctx" else null;
            try assertEngineErrorOrOk(engine.decrypt(a, io, "pw", label, scratch), a);
        }
    }

    // 4) Random-length grows and shrinks built around a real container (changes the
    //    frame layout / trailing bytes without staying byte-aligned to it).
    {
        var i: usize = 0;
        while (i < ITERS) : (i += 1) {
            const extra = rand.intRangeAtMost(usize, 0, 64);
            const keep = rand.intRangeAtMost(usize, 0, base.len);
            const mutated = try a.alloc(u8, keep + extra);
            defer a.free(mutated);
            @memcpy(mutated[0..keep], base[0..keep]);
            rand.bytes(mutated[keep..]);
            try assertEngineErrorOrOk(engine.decrypt(a, io, "pw", null, mutated), a);
        }
    }
}

comptime {
    _ = TestEnv;
}
