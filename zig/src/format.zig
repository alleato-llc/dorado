//! The on-disk container format (magic "DRDO", version 4; version 3 still read):
//! header marshalling and parse. Matches the Rust reference and the other ports
//! byte-for-byte. All multi-byte integers are big-endian.

const std = @import("std");
const mem = std.mem;
const tf = @import("threefish.zig");

pub const Variant = tf.Variant;

pub const MAGIC = "DRDO";
pub const VERSION = 4;
pub const DEFAULT_CHUNK_BYTES: u32 = 64 * 1024;
pub const MAX_CHUNK_BYTES: u32 = 1 << 30;
pub const MAX_LABEL_LEN = 4096;
pub const MAC_KEY_LEN = 32;
pub const TAG_LEN = 32;

pub const Mac = enum(u8) {
    hmac = 1,
    skein = 2,
    blake3 = 3,

    pub fn fromCode(c: u8) ?Mac {
        return switch (c) {
            1 => .hmac,
            2 => .skein,
            3 => .blake3,
            else => null,
        };
    }
};

pub const KdfKind = enum(u8) {
    argon2id = 1,
    scrypt = 2,
    pbkdf2 = 3,
};

pub const Kdf = union(KdfKind) {
    argon2id: struct { m_cost: u32, t_cost: u32, p_cost: u32 },
    scrypt: struct { log_n: u8, r: u32, p: u32 },
    pbkdf2: struct { rounds: u32 },

    pub fn mkArgon2id(m_cost_kib: u32, t_cost: u32, p_cost: u32) Kdf {
        return .{ .argon2id = .{ .m_cost = m_cost_kib, .t_cost = t_cost, .p_cost = p_cost } };
    }
    pub fn mkScrypt(log_n: u8, r: u32, p: u32) Kdf {
        return .{ .scrypt = .{ .log_n = log_n, .r = r, .p = p } };
    }
    pub fn mkPbkdf2(rounds: u32) Kdf {
        return .{ .pbkdf2 = .{ .rounds = rounds } };
    }
};

pub const Error = error{
    BadMagic,
    UnsupportedVersion,
    UnknownVariant,
    UnknownKdf,
    UnknownPrf,
    UnknownMac,
    LabelTooLong,
    Truncated,
};

pub const Header = struct {
    version: u8,
    variant: Variant,
    kdf: Kdf,
    mac: Mac,
    chunk_size: u32,
    salt: [256]u8,
    salt_len: usize,
    tweak: [16]u8,
    iv: [128]u8,
    label: [MAX_LABEL_LEN]u8,
    label_len: usize,

    pub fn ivSlice(self: *const Header) []const u8 {
        return self.iv[0..self.variant.keyLen()];
    }
    pub fn labelSlice(self: *const Header) []const u8 {
        return self.label[0..self.label_len];
    }
    pub fn saltSlice(self: *const Header) []const u8 {
        return self.salt[0..self.salt_len];
    }
};

/// Serialize a header into out, returning the number of bytes written.
pub fn marshal(h: *const Header, out: []u8) usize {
    var n: usize = 0;
    @memcpy(out[0..4], MAGIC);
    n += 4;
    out[n] = h.version;
    n += 1;
    out[n] = @intFromEnum(h.variant);
    n += 1;
    switch (h.kdf) {
        .argon2id => |a| {
            out[n] = 1;
            n += 1;
            mem.writeInt(u32, out[n..][0..4], a.m_cost, .big);
            n += 4;
            mem.writeInt(u32, out[n..][0..4], a.t_cost, .big);
            n += 4;
            mem.writeInt(u32, out[n..][0..4], a.p_cost, .big);
            n += 4;
        },
        .scrypt => |s| {
            out[n] = 2;
            n += 1;
            out[n] = s.log_n;
            n += 1;
            mem.writeInt(u32, out[n..][0..4], s.r, .big);
            n += 4;
            mem.writeInt(u32, out[n..][0..4], s.p, .big);
            n += 4;
        },
        .pbkdf2 => |p| {
            out[n] = 3;
            n += 1;
            mem.writeInt(u32, out[n..][0..4], p.rounds, .big);
            n += 4;
            out[n] = 1; // prf id = HMAC-SHA256
            n += 1;
        },
    }
    out[n] = @intFromEnum(h.mac);
    n += 1;
    mem.writeInt(u32, out[n..][0..4], h.chunk_size, .big);
    n += 4;
    out[n] = @intCast(h.salt_len);
    n += 1;
    @memcpy(out[n .. n + h.salt_len], h.saltSlice());
    n += h.salt_len;
    @memcpy(out[n .. n + 16], &h.tweak);
    n += 16;
    const iv_len = h.variant.keyLen();
    @memcpy(out[n .. n + iv_len], h.ivSlice());
    n += iv_len;
    if (h.version >= 4) {
        mem.writeInt(u16, out[n..][0..2], @intCast(h.label_len), .big);
        n += 2;
        @memcpy(out[n .. n + h.label_len], h.labelSlice());
        n += h.label_len;
    }
    return n;
}

/// A minimal byte-reader abstraction so the parser works over a file or a buffer.
pub const Reader = struct {
    ctx: *anyopaque,
    readFn: *const fn (ctx: *anyopaque, buf: []u8) usize,

    pub fn readFull(self: Reader, buf: []u8) bool {
        var got: usize = 0;
        while (got < buf.len) {
            const n = self.readFn(self.ctx, buf[got..]);
            if (n == 0) return false;
            got += n;
        }
        return true;
    }
};

fn rdU8(r: Reader) Error!u8 {
    var b: [1]u8 = undefined;
    if (!r.readFull(&b)) return Error.Truncated;
    return b[0];
}

fn rdU16(r: Reader) Error!u16 {
    var b: [2]u8 = undefined;
    if (!r.readFull(&b)) return Error.Truncated;
    return mem.readInt(u16, &b, .big);
}

fn rdU32(r: Reader) Error!u32 {
    var b: [4]u8 = undefined;
    if (!r.readFull(&b)) return Error.Truncated;
    return mem.readInt(u32, &b, .big);
}

/// Read a header from r, leaving it positioned at the first frame.
pub fn read(r: Reader, h: *Header) Error!void {
    var magic: [4]u8 = undefined;
    if (!r.readFull(&magic)) return Error.Truncated;
    if (!mem.eql(u8, &magic, MAGIC)) return Error.BadMagic;
    h.version = try rdU8(r);
    if (h.version != 3 and h.version != VERSION) return Error.UnsupportedVersion;
    h.variant = tf.Variant.fromCode(try rdU8(r)) orelse return Error.UnknownVariant;

    const kdf_id = try rdU8(r);
    switch (kdf_id) {
        1 => h.kdf = Kdf.mkArgon2id(try rdU32(r), try rdU32(r), try rdU32(r)),
        2 => h.kdf = Kdf.mkScrypt(try rdU8(r), try rdU32(r), try rdU32(r)),
        3 => {
            const rounds = try rdU32(r);
            if (try rdU8(r) != 1) return Error.UnknownPrf;
            h.kdf = Kdf.mkPbkdf2(rounds);
        },
        else => return Error.UnknownKdf,
    }

    h.mac = Mac.fromCode(try rdU8(r)) orelse return Error.UnknownMac;
    h.chunk_size = try rdU32(r);
    h.salt_len = try rdU8(r);
    if (!r.readFull(h.salt[0..h.salt_len])) return Error.Truncated;
    if (!r.readFull(&h.tweak)) return Error.Truncated;
    if (!r.readFull(h.iv[0..h.variant.keyLen()])) return Error.Truncated;
    if (h.version >= 4) {
        const label_len = try rdU16(r);
        if (label_len > MAX_LABEL_LEN) return Error.LabelTooLong;
        if (!r.readFull(h.label[0..label_len])) return Error.Truncated;
        h.label_len = label_len;
    } else {
        h.label_len = 0;
    }
}
