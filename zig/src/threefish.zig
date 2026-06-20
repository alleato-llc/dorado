//! From-scratch Threefish (256/512/1024-bit), the tweakable block cipher at the
//! core of Skein (Skein 1.3, including the round-3 NIST C240 tweak), plus CTR mode.
//! Zig port of the dorado Rust crate; keys, tweaks, and blocks are little-endian.
//! Zig's native u64 with wrapping operators makes the ARX direct. Educational and
//! unaudited.

const std = @import("std");
const mem = std.mem;
const rotl = std.math.rotl;
const rotr = std.math.rotr;

/// Skein 1.3 key-schedule constant (the round-3 NIST value). Do not change.
const C240: u64 = 0x1BD11BDAA9FC1A22;

// Per-variant rotation and permutation tables (Skein 1.3). Verified against
// official test vectors and must not be changed.
const ROT256 = [2][8]u6{
    .{ 14, 52, 23, 5, 25, 46, 58, 32 },
    .{ 16, 57, 40, 37, 33, 12, 22, 32 },
};
const PERM256 = [4]usize{ 0, 3, 2, 1 };

const ROT512 = [4][8]u6{
    .{ 46, 33, 17, 44, 39, 13, 25, 8 },
    .{ 36, 27, 49, 9, 30, 50, 29, 35 },
    .{ 19, 14, 36, 54, 34, 10, 39, 56 },
    .{ 37, 42, 39, 56, 24, 17, 43, 22 },
};
const PERM512 = [8]usize{ 2, 1, 4, 7, 6, 5, 0, 3 };

const ROT1024 = [8][8]u6{
    .{ 24, 38, 33, 5, 41, 16, 31, 9 },
    .{ 13, 19, 4, 20, 9, 34, 44, 48 },
    .{ 8, 10, 51, 48, 37, 56, 47, 35 },
    .{ 47, 55, 13, 41, 31, 51, 46, 52 },
    .{ 8, 49, 34, 47, 12, 4, 19, 23 },
    .{ 17, 18, 41, 28, 47, 53, 42, 31 },
    .{ 22, 23, 59, 16, 44, 42, 44, 37 },
    .{ 37, 52, 17, 25, 30, 41, 25, 20 },
};
const PERM1024 = [16]usize{ 0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1 };

pub const Variant = enum(u8) {
    t256 = 0,
    t512 = 1,
    t1024 = 2,

    pub fn fromCode(code: u8) ?Variant {
        return switch (code) {
            0 => .t256,
            1 => .t512,
            2 => .t1024,
            else => null,
        };
    }

    /// The variant's key/block/IV length in bytes.
    pub fn keyLen(self: Variant) usize {
        return switch (self) {
            .t256 => 32,
            .t512 => 64,
            .t1024 => 128,
        };
    }
};

pub const Threefish = struct {
    ek: [17]u64, // nw key words + parity word (nw <= 16)
    et: [3]u64,
    rot: []const [8]u6,
    perm: []const usize,
    rounds: usize,
    nw: usize,
    block_bytes: usize,

    pub fn init(variant: Variant, key: []const u8, tweak: []const u8) Threefish {
        var tf: Threefish = undefined;
        switch (variant) {
            .t256 => {
                tf.nw = 4;
                tf.rounds = 72;
                tf.rot = &ROT256;
                tf.perm = &PERM256;
            },
            .t512 => {
                tf.nw = 8;
                tf.rounds = 72;
                tf.rot = &ROT512;
                tf.perm = &PERM512;
            },
            .t1024 => {
                tf.nw = 16;
                tf.rounds = 80;
                tf.rot = &ROT1024;
                tf.perm = &PERM1024;
            },
        }
        tf.block_bytes = tf.nw * 8;
        std.debug.assert(key.len == tf.block_bytes);
        std.debug.assert(tweak.len == 16);
        var parity: u64 = C240;
        for (0..tf.nw) |i| {
            const w = mem.readInt(u64, key[i * 8 ..][0..8], .little);
            tf.ek[i] = w;
            parity ^= w;
        }
        tf.ek[tf.nw] = parity;
        const t0 = mem.readInt(u64, tweak[0..8], .little);
        const t1 = mem.readInt(u64, tweak[8..16], .little);
        tf.et = .{ t0, t1, t0 ^ t1 };
        return tf;
    }

    fn addSubkey(self: *const Threefish, state: []u64, s: usize) void {
        const nw = self.nw;
        for (0..nw) |i| {
            var k = self.ek[(s + i) % (nw + 1)];
            if (i == nw - 3) {
                k +%= self.et[s % 3];
            } else if (i == nw - 2) {
                k +%= self.et[(s + 1) % 3];
            } else if (i == nw - 1) {
                k +%= @as(u64, s);
            }
            state[i] +%= k;
        }
    }

    fn subSubkey(self: *const Threefish, state: []u64, s: usize) void {
        const nw = self.nw;
        for (0..nw) |i| {
            var k = self.ek[(s + i) % (nw + 1)];
            if (i == nw - 3) {
                k +%= self.et[s % 3];
            } else if (i == nw - 2) {
                k +%= self.et[(s + 1) % 3];
            } else if (i == nw - 1) {
                k +%= @as(u64, s);
            }
            state[i] -%= k;
        }
    }

    fn encryptState(self: *const Threefish, state: []u64) void {
        const nw = self.nw;
        var scratch: [16]u64 = undefined;
        var r: usize = 0;
        while (r < self.rounds) : (r += 1) {
            if (r % 4 == 0) self.addSubkey(state, r / 4);
            var j: usize = 0;
            while (j < nw / 2) : (j += 1) {
                const x0 = state[2 * j];
                const x1 = state[2 * j + 1];
                const y0 = x0 +% x1;
                const y1 = rotl(u64, x1, self.rot[j][r % 8]) ^ y0;
                state[2 * j] = y0;
                state[2 * j + 1] = y1;
            }
            for (0..nw) |i| scratch[i] = state[self.perm[i]];
            @memcpy(state, scratch[0..nw]);
        }
        self.addSubkey(state, self.rounds / 4);
    }

    fn decryptState(self: *const Threefish, state: []u64) void {
        const nw = self.nw;
        var scratch: [16]u64 = undefined;
        self.subSubkey(state, self.rounds / 4);
        var r: isize = @as(isize, @intCast(self.rounds)) - 1;
        while (r >= 0) : (r -= 1) {
            const ru: usize = @intCast(r);
            for (0..nw) |i| scratch[self.perm[i]] = state[i];
            @memcpy(state, scratch[0..nw]);
            var j: usize = 0;
            while (j < nw / 2) : (j += 1) {
                const y0 = state[2 * j];
                const y1 = state[2 * j + 1];
                const x1 = rotr(u64, y1 ^ y0, self.rot[j][ru % 8]);
                const x0 = y0 -% x1;
                state[2 * j] = x0;
                state[2 * j + 1] = x1;
            }
            if (ru % 4 == 0) self.subSubkey(state, ru / 4);
        }
    }

    pub fn encryptBlock(self: *const Threefish, out: []u8, in: []const u8) void {
        var state: [16]u64 = undefined;
        for (0..self.nw) |i| state[i] = mem.readInt(u64, in[i * 8 ..][0..8], .little);
        self.encryptState(state[0..self.nw]);
        for (0..self.nw) |i| mem.writeInt(u64, out[i * 8 ..][0..8], state[i], .little);
    }

    pub fn decryptBlock(self: *const Threefish, out: []u8, in: []const u8) void {
        var state: [16]u64 = undefined;
        for (0..self.nw) |i| state[i] = mem.readInt(u64, in[i * 8 ..][0..8], .little);
        self.decryptState(state[0..self.nw]);
        for (0..self.nw) |i| mem.writeInt(u64, out[i * 8 ..][0..8], state[i], .little);
    }

    pub fn newCtr(self: *const Threefish, iv: []const u8) Ctr {
        std.debug.assert(iv.len == self.block_bytes);
        var ctr = Ctr{ .tf = self, .counter = undefined };
        @memcpy(ctr.counter[0..self.block_bytes], iv);
        return ctr;
    }
};

/// A resumable CTR keystream: apply() may be called per chunk, the counter carrying
/// across calls, so a file streams in constant memory and stays identical to
/// whole-file CTR (non-final chunks are whole blocks).
pub const Ctr = struct {
    tf: *const Threefish,
    counter: [128]u8,

    pub fn apply(self: *Ctr, buf: []u8) void {
        const bs = self.tf.block_bytes;
        var ks: [128]u8 = undefined;
        var off: usize = 0;
        while (off < buf.len) : (off += bs) {
            self.tf.encryptBlock(ks[0..bs], self.counter[0..bs]);
            const n = @min(bs, buf.len - off);
            for (0..n) |j| buf[off + j] ^= ks[j];
            // increment the counter as a big-endian integer
            var i: isize = @as(isize, @intCast(bs)) - 1;
            while (i >= 0) : (i -= 1) {
                const idx: usize = @intCast(i);
                self.counter[idx] +%= 1;
                if (self.counter[idx] != 0) break;
            }
        }
    }
};
