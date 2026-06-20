//! From-scratch Skein-512 hash and MAC (Skein 1.3), built on Threefish-512 via UBI.
//! Incremental (streams in constant memory) with one-shot helpers. Zig port of the
//! dorado Rust crate's skein module.

const std = @import("std");
const mem = std.mem;
const tf = @import("threefish.zig");

const BLOCK = 64;

// UBI block type values (the 6-bit type field of the tweak).
const T_KEY: u64 = 0;
const T_CFG: u64 = 4;
const T_MSG: u64 = 48;
const T_OUT: u64 = 63;

fn buildTweak(position: u64, ty: u64, first: bool, last: bool) [16]u8 {
    var t1 = ty << 56;
    if (first) t1 |= @as(u64, 1) << 62;
    if (last) t1 |= @as(u64, 1) << 63;
    var tw: [16]u8 = undefined;
    mem.writeInt(u64, tw[0..8], position, .little);
    mem.writeInt(u64, tw[8..16], t1, .little);
    return tw;
}

// One full UBI pass, chaining msg into the chaining value g.
fn ubi(g: *[64]u8, msg: []const u8, ty: u64) void {
    var offset: usize = 0;
    var position: u64 = 0;
    var first = true;
    while (true) {
        const take = @min(msg.len - offset, BLOCK);
        var block = [_]u8{0} ** BLOCK;
        @memcpy(block[0..take], msg[offset .. offset + take]);
        position += take;
        offset += take;
        const last = offset >= msg.len;
        const tw = buildTweak(position, ty, first, last);
        const cipher = tf.Threefish.init(.t512, g, &tw);
        var enc: [BLOCK]u8 = undefined;
        cipher.encryptBlock(&enc, &block);
        for (0..BLOCK) |i| g[i] = enc[i] ^ block[i];
        first = false;
        if (last) break;
    }
}

fn configBlock(out_bits: u64) [32]u8 {
    var c = [_]u8{0} ** 32;
    c[0] = 'S';
    c[1] = 'H';
    c[2] = 'A';
    c[3] = '3';
    c[4] = 1; // version 1 (16-bit little-endian)
    mem.writeInt(u64, c[8..16], out_bits, .little);
    return c;
}

fn outputInto(g: *const [64]u8, out: []u8) void {
    var counter: u64 = 0;
    var written: usize = 0;
    while (written < out.len) {
        var block: [64]u8 = g.*;
        var ctr: [8]u8 = undefined;
        mem.writeInt(u64, &ctr, counter, .little);
        ubi(&block, &ctr, T_OUT);
        const n = @min(BLOCK, out.len - written);
        @memcpy(out[written .. written + n], block[0..n]);
        written += n;
        counter += 1;
    }
}

/// Incremental Skein-512 hash or MAC, holding back the final block until done.
pub const Skein512 = struct {
    g: [64]u8,
    buffer: [64]u8,
    buffer_len: usize,
    position: u64,
    first: bool,
    out_len: usize,

    pub fn init(out_len: usize) Skein512 {
        var s = Skein512{
            .g = [_]u8{0} ** 64,
            .buffer = undefined,
            .buffer_len = 0,
            .position = 0,
            .first = true,
            .out_len = out_len,
        };
        const cfg = configBlock(@as(u64, out_len) * 8);
        ubi(&s.g, &cfg, T_CFG);
        return s;
    }

    pub fn initMac(key: []const u8, out_len: usize) Skein512 {
        var s = Skein512{
            .g = [_]u8{0} ** 64,
            .buffer = undefined,
            .buffer_len = 0,
            .position = 0,
            .first = true,
            .out_len = out_len,
        };
        if (key.len > 0) ubi(&s.g, key, T_KEY);
        const cfg = configBlock(@as(u64, out_len) * 8);
        ubi(&s.g, &cfg, T_CFG);
        return s;
    }

    fn commit(self: *Skein512, block: *const [64]u8, nbytes: usize, last: bool) void {
        self.position += nbytes;
        const tw = buildTweak(self.position, T_MSG, self.first, last);
        const cipher = tf.Threefish.init(.t512, &self.g, &tw);
        var enc: [64]u8 = undefined;
        cipher.encryptBlock(&enc, block);
        for (0..64) |i| self.g[i] = enc[i] ^ block[i];
        self.first = false;
    }

    pub fn update(self: *Skein512, data: []const u8) void {
        var d = data;
        if (d.len == 0) return;
        if (self.buffer_len > 0) {
            const take = @min(BLOCK - self.buffer_len, d.len);
            @memcpy(self.buffer[self.buffer_len .. self.buffer_len + take], d[0..take]);
            self.buffer_len += take;
            d = d[take..];
            if (self.buffer_len == BLOCK and d.len > 0) {
                self.commit(&self.buffer, BLOCK, false);
                self.buffer_len = 0;
            }
        }
        while (d.len > BLOCK) {
            self.commit(d[0..BLOCK], BLOCK, false);
            d = d[BLOCK..];
        }
        if (d.len > 0) {
            @memcpy(self.buffer[0..d.len], d);
            self.buffer_len = d.len;
        }
    }

    /// Write out_len bytes into out. Does not change the hasher state.
    pub fn finalize(self: *const Skein512, out: []u8) void {
        var tmp = self.*;
        var block = [_]u8{0} ** 64;
        @memcpy(block[0..tmp.buffer_len], tmp.buffer[0..tmp.buffer_len]);
        tmp.commit(&block, tmp.buffer_len, true);
        outputInto(&tmp.g, out);
    }
};

pub fn hash(out_len: usize, msg: []const u8, out: []u8) void {
    var s = Skein512.init(out_len);
    s.update(msg);
    s.finalize(out);
}

pub fn mac(key: []const u8, out_len: usize, msg: []const u8, out: []u8) void {
    var s = Skein512.initMac(key, out_len);
    s.update(msg);
    s.finalize(out);
}
