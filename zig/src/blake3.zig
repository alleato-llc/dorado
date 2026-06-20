//! From-scratch BLAKE3 hash and keyed MAC, using the streaming chunk-stack
//! algorithm. The inherent finalize is an extendable-output function. Zig port of
//! the dorado Rust crate's blake3 module.

const std = @import("std");
const mem = std.mem;
const rotr = std.math.rotr;

const BLOCK_BYTES = 64;
const CHUNK_BYTES = 1024;

const CHUNK_START: u32 = 1 << 0;
const CHUNK_END: u32 = 1 << 1;
const FLAG_PARENT: u32 = 1 << 2;
const FLAG_ROOT: u32 = 1 << 3;
const KEYED_HASH: u32 = 1 << 4;

const IV = [8]u32{
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
};

const MSG_PERMUTATION = [16]usize{ 2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8 };

fn g(s: *[16]u32, a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) void {
    s[a] = s[a] +% s[b] +% mx;
    s[d] = rotr(u32, s[d] ^ s[a], 16);
    s[c] = s[c] +% s[d];
    s[b] = rotr(u32, s[b] ^ s[c], 12);
    s[a] = s[a] +% s[b] +% my;
    s[d] = rotr(u32, s[d] ^ s[a], 8);
    s[c] = s[c] +% s[d];
    s[b] = rotr(u32, s[b] ^ s[c], 7);
}

fn compress(cv: *const [8]u32, block: *const [16]u32, counter: u64, b_len: u32, flags: u32) [16]u32 {
    var state = [16]u32{
        cv[0],                       cv[1],                              cv[2],  cv[3],
        cv[4],                       cv[5],                              cv[6],  cv[7],
        IV[0],                       IV[1],                              IV[2],  IV[3],
        @truncate(counter),          @truncate(counter >> 32),          b_len,  flags,
    };
    var m = block.*;
    var round: usize = 0;
    while (round < 7) : (round += 1) {
        g(&state, 0, 4, 8, 12, m[0], m[1]);
        g(&state, 1, 5, 9, 13, m[2], m[3]);
        g(&state, 2, 6, 10, 14, m[4], m[5]);
        g(&state, 3, 7, 11, 15, m[6], m[7]);
        g(&state, 0, 5, 10, 15, m[8], m[9]);
        g(&state, 1, 6, 11, 12, m[10], m[11]);
        g(&state, 2, 7, 8, 13, m[12], m[13]);
        g(&state, 3, 4, 9, 14, m[14], m[15]);
        if (round < 6) {
            var permuted: [16]u32 = undefined;
            for (0..16) |i| permuted[i] = m[MSG_PERMUTATION[i]];
            m = permuted;
        }
    }
    for (0..8) |i| {
        state[i] ^= state[i + 8];
        state[i + 8] ^= cv[i];
    }
    return state;
}

fn wordsFromBlock(b: []const u8) [16]u32 {
    var padded = [_]u8{0} ** BLOCK_BYTES;
    @memcpy(padded[0..b.len], b);
    var words: [16]u32 = undefined;
    for (0..16) |i| words[i] = mem.readInt(u32, padded[i * 4 ..][0..4], .little);
    return words;
}

const Output = struct {
    input_cv: [8]u32,
    block: [16]u32,
    counter: u64,
    b_len: u32,
    flags: u32,

    fn chainingValue(self: *const Output) [8]u32 {
        const full = compress(&self.input_cv, &self.block, self.counter, self.b_len, self.flags);
        return full[0..8].*;
    }

    fn rootOutput(self: *const Output, out: []u8) void {
        var counter: u64 = 0;
        var written: usize = 0;
        while (written < out.len) {
            const words = compress(&self.input_cv, &self.block, counter, self.b_len, self.flags | FLAG_ROOT);
            for (words) |w| {
                if (written >= out.len) break;
                var wb: [4]u8 = undefined;
                mem.writeInt(u32, &wb, w, .little);
                const n = @min(4, out.len - written);
                @memcpy(out[written .. written + n], wb[0..n]);
                written += n;
            }
            counter += 1;
        }
    }
};

const ChunkState = struct {
    cv: [8]u32,
    chunk_counter: u64,
    block: [BLOCK_BYTES]u8,
    block_len: usize,
    blocks_compressed: u64,
    flags: u32,

    fn init(key: *const [8]u32, chunk_counter: u64, flags: u32) ChunkState {
        return .{
            .cv = key.*,
            .chunk_counter = chunk_counter,
            .block = [_]u8{0} ** BLOCK_BYTES,
            .block_len = 0,
            .blocks_compressed = 0,
            .flags = flags,
        };
    }

    fn len(self: *const ChunkState) usize {
        return BLOCK_BYTES * @as(usize, @intCast(self.blocks_compressed)) + self.block_len;
    }

    fn startFlag(self: *const ChunkState) u32 {
        return if (self.blocks_compressed == 0) CHUNK_START else 0;
    }

    fn update(self: *ChunkState, data: []const u8) void {
        var d = data;
        while (d.len > 0) {
            if (self.block_len == BLOCK_BYTES) {
                const bw = wordsFromBlock(&self.block);
                const out = compress(&self.cv, &bw, self.chunk_counter, BLOCK_BYTES, self.flags | self.startFlag());
                self.cv = out[0..8].*;
                self.blocks_compressed += 1;
                self.block = [_]u8{0} ** BLOCK_BYTES;
                self.block_len = 0;
            }
            const take = @min(BLOCK_BYTES - self.block_len, d.len);
            @memcpy(self.block[self.block_len .. self.block_len + take], d[0..take]);
            self.block_len += take;
            d = d[take..];
        }
    }

    fn output(self: *const ChunkState) Output {
        return .{
            .input_cv = self.cv,
            .block = wordsFromBlock(self.block[0..self.block_len]),
            .counter = self.chunk_counter,
            .b_len = @intCast(self.block_len),
            .flags = self.flags | self.startFlag() | CHUNK_END,
        };
    }
};

fn parentOutput(left: *const [8]u32, right: *const [8]u32, key: *const [8]u32, flags: u32) Output {
    var block: [16]u32 = undefined;
    @memcpy(block[0..8], left);
    @memcpy(block[8..16], right);
    return .{ .input_cv = key.*, .block = block, .counter = 0, .b_len = BLOCK_BYTES, .flags = flags | FLAG_PARENT };
}

fn parentCv(left: *const [8]u32, right: *const [8]u32, key: *const [8]u32, flags: u32) [8]u32 {
    const o = parentOutput(left, right, key, flags);
    return o.chainingValue();
}

/// An incremental BLAKE3 hash/MAC (chunk-stack streaming).
pub const Hasher = struct {
    key: [8]u32,
    flags: u32,
    chunk: ChunkState,
    cv_stack: [54][8]u32, // max input 2^64 -> depth <= 54
    cv_stack_len: usize,

    pub fn init() Hasher {
        return initInternal(IV, 0);
    }

    pub fn initKeyed(key32: *const [32]u8) Hasher {
        var kw: [8]u32 = undefined;
        for (0..8) |i| kw[i] = mem.readInt(u32, key32[i * 4 ..][0..4], .little);
        return initInternal(kw, KEYED_HASH);
    }

    fn initInternal(key: [8]u32, flags: u32) Hasher {
        return .{
            .key = key,
            .flags = flags,
            .chunk = ChunkState.init(&key, 0, flags),
            .cv_stack = undefined,
            .cv_stack_len = 0,
        };
    }

    fn addChunkCv(self: *Hasher, new_cv: [8]u32, total_chunks: u64) void {
        var cv = new_cv;
        var total = total_chunks;
        while (total & 1 == 0) {
            self.cv_stack_len -= 1;
            cv = parentCv(&self.cv_stack[self.cv_stack_len], &cv, &self.key, self.flags);
            total >>= 1;
        }
        self.cv_stack[self.cv_stack_len] = cv;
        self.cv_stack_len += 1;
    }

    pub fn update(self: *Hasher, data: []const u8) void {
        var d = data;
        while (d.len > 0) {
            if (self.chunk.len() == CHUNK_BYTES) {
                const chunk_cv = self.chunk.output().chainingValue();
                const total = self.chunk.chunk_counter + 1;
                self.addChunkCv(chunk_cv, total);
                self.chunk = ChunkState.init(&self.key, total, self.flags);
            }
            const take = @min(CHUNK_BYTES - self.chunk.len(), d.len);
            self.chunk.update(d[0..take]);
            d = d[take..];
        }
    }

    /// Write the digest into out (any length; an XOF for out.len > 32).
    pub fn finalize(self: *const Hasher, out: []u8) void {
        var o = self.chunk.output();
        var i: isize = @as(isize, @intCast(self.cv_stack_len)) - 1;
        while (i >= 0) : (i -= 1) {
            const idx: usize = @intCast(i);
            const cv = o.chainingValue();
            o = parentOutput(&self.cv_stack[idx], &cv, &self.key, self.flags);
        }
        o.rootOutput(out);
    }
};

pub fn hash(out_len: usize, data: []const u8, out: []u8) void {
    _ = out_len;
    var h = Hasher.init();
    h.update(data);
    h.finalize(out);
}

pub fn keyedMac(key32: *const [32]u8, data: []const u8, out: []u8) void {
    var h = Hasher.initKeyed(key32);
    h.update(data);
    h.finalize(out);
}
