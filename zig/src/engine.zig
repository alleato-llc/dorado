//! The construction over the Threefish cipher: the authenticated chunked password
//! container, raw CTR, and inspect. Streams over Reader/Writer callbacks in constant
//! memory (files larger than RAM are fine), matching the Rust reference. Slice
//! convenience wrappers are provided. The on-disk output is byte-for-byte identical
//! to the other ports, so `.mahi` files are cross-compatible.
//!
//! Educational and unaudited.

const std = @import("std");
const mem = std.mem;
const tf = @import("threefish.zig");
const fmt = @import("format.zig");
const kdf = @import("kdf.zig");
const mac_mod = @import("mac.zig");

pub const Variant = tf.Variant;
pub const Kdf = fmt.Kdf;
pub const Mac = fmt.Mac;
pub const Header = fmt.Header;

const FRAME_DOMAIN = "DRDOchnk";
const HEADER_MAX = 8192;

pub const Reader = fmt.Reader;

/// A byte sink: returns true on success.
pub const Writer = struct {
    ctx: *anyopaque,
    writeFn: *const fn (ctx: *anyopaque, bytes: []const u8) bool,

    pub fn write(self: Writer, bytes: []const u8) Error!void {
        if (!self.writeFn(self.ctx, bytes)) return Error.WriteFailed;
    }
};

pub const Error = error{
    LabelTooLong,
    InvalidChunkSize,
    BadContainer,
    AuthFailed,
    Truncated,
    WriteFailed,
    OutOfMemory,
    Rng,
    KdfFailed,
    HostileCost,
} || fmt.Error || kdf.Error;

pub const Options = struct {
    variant: Variant = .t256,
    kdf: Kdf = Kdf.mkArgon2id(64 * 1024, 3, 1),
    mac: Mac = .skein,
    tweak: [16]u8 = [_]u8{0} ** 16,
    chunk_size: u32 = fmt.DEFAULT_CHUNK_BYTES,
    label: []const u8 = "",
};

pub const ContainerInfo = struct {
    version: u8,
    variant: Variant,
    mac: Mac,
    kdf: Kdf,
    chunk_size: u32,
    salt_len: usize,
    tweak: [16]u8,
    label: [fmt.MAX_LABEL_LEN]u8,
    label_len: usize,

    pub fn labelSlice(self: *const ContainerInfo) []const u8 {
        return self.label[0..self.label_len];
    }
};

fn writeBE32(buf: []u8, v: u32) void {
    mem.writeInt(u32, buf[0..4], v, .big);
}

// Build the AAD for a frame into `dst`, returning the length used.
fn buildAad(dst: []u8, header_bytes: []const u8, index: u64, is_last: bool, ct: []const u8) usize {
    var n: usize = 0;
    @memcpy(dst[0..8], FRAME_DOMAIN);
    n += 8;
    if (index == 0) {
        @memcpy(dst[n .. n + header_bytes.len], header_bytes);
        n += header_bytes.len;
    }
    mem.writeInt(u64, dst[n..][0..8], index, .big);
    n += 8;
    dst[n] = if (is_last) 1 else 0;
    n += 1;
    writeBE32(dst[n..], @intCast(ct.len));
    n += 4;
    @memcpy(dst[n .. n + ct.len], ct);
    n += ct.len;
    return n;
}

fn writeFrame(w: Writer, is_last: bool, ct: []const u8, tag: *const [32]u8) Error!void {
    var head: [5]u8 = undefined;
    head[0] = if (is_last) 1 else 0;
    writeBE32(head[1..], @intCast(ct.len));
    try w.write(&head);
    if (ct.len > 0) try w.write(ct);
    try w.write(tag);
}

pub fn encryptStream(
    allocator: mem.Allocator,
    io: std.Io,
    password: []const u8,
    opts: Options,
    r: Reader,
    w: Writer,
) Error!void {
    if (opts.label.len > fmt.MAX_LABEL_LEN) return Error.LabelTooLong;
    const v = opts.variant;
    const bl = v.keyLen();
    if (opts.chunk_size == 0 or opts.chunk_size > fmt.MAX_CHUNK_BYTES or opts.chunk_size % bl != 0)
        return Error.InvalidChunkSize;

    var salt: [16]u8 = undefined;
    var iv: [128]u8 = undefined;
    io.randomSecure(&salt) catch return Error.Rng;
    io.randomSecure(iv[0..bl]) catch return Error.Rng;

    var keymat: [160]u8 = undefined;
    try kdf.derive(allocator, io, opts.kdf, password, &salt, keymat[0 .. bl + 32]);
    const enc_key = keymat[0..bl];
    const mac_key = keymat[bl .. bl + 32][0..32];

    var h: Header = undefined;
    h.version = fmt.VERSION;
    h.variant = v;
    h.kdf = opts.kdf;
    h.mac = opts.mac;
    h.chunk_size = opts.chunk_size;
    @memcpy(h.salt[0..16], &salt);
    h.salt_len = 16;
    h.tweak = opts.tweak;
    @memcpy(h.iv[0..bl], iv[0..bl]);
    @memcpy(h.label[0..opts.label.len], opts.label);
    h.label_len = opts.label.len;

    var hb: [HEADER_MAX]u8 = undefined;
    const hb_len = fmt.marshal(&h, &hb);

    var cipher = tf.Threefish.init(v, enc_key, &opts.tweak);
    var ctr = cipher.newCtr(iv[0..bl]);

    try w.write(hb[0..hb_len]);

    const cs = opts.chunk_size;
    const cur = try allocator.alloc(u8, cs);
    defer allocator.free(cur);
    const nxt = try allocator.alloc(u8, cs);
    defer allocator.free(nxt);
    const aad = try allocator.alloc(u8, 8 + hb_len + 13 + cs);
    defer allocator.free(aad);

    var cur_buf = cur;
    var nxt_buf = nxt;
    var cur_len = readSome(r, cur_buf);
    var index: u64 = 0;
    while (true) {
        const nxt_len = readSome(r, nxt_buf);
        const is_last = nxt_len == 0;
        ctr.apply(cur_buf[0..cur_len]);
        var tag: [32]u8 = undefined;
        const aad_len = buildAad(aad, hb[0..hb_len], index, is_last, cur_buf[0..cur_len]);
        mac_mod.tag(opts.mac, mac_key, aad[0..aad_len], &tag);
        try writeFrame(w, is_last, cur_buf[0..cur_len], &tag);
        if (is_last) break;
        index += 1;
        const tmp = cur_buf;
        cur_buf = nxt_buf;
        nxt_buf = tmp;
        cur_len = nxt_len;
    }
}

// Read up to buf.len bytes; a short count means end of input.
fn readSome(r: Reader, buf: []u8) usize {
    var got: usize = 0;
    while (got < buf.len) {
        const n = r.readFn(r.ctx, buf[got..]);
        if (n == 0) break;
        got += n;
    }
    return got;
}

pub fn decryptStream(
    allocator: mem.Allocator,
    io: std.Io,
    password: []const u8,
    expected_label: ?[]const u8,
    r: Reader,
    w: Writer,
) Error!void {
    var h: Header = undefined;
    try fmt.read(r, &h);
    if (expected_label) |el| {
        if (!mem.eql(u8, el, h.labelSlice())) return Error.BadContainer;
    }
    const bl = h.variant.keyLen();
    if (h.chunk_size == 0 or h.chunk_size > fmt.MAX_CHUNK_BYTES or h.chunk_size % bl != 0)
        return Error.InvalidChunkSize;
    try kdf.validate(h.kdf);

    var keymat: [160]u8 = undefined;
    try kdf.derive(allocator, io, h.kdf, password, h.saltSlice(), keymat[0 .. bl + 32]);
    const enc_key = keymat[0..bl];
    const mac_key = keymat[bl .. bl + 32][0..32];

    var hb: [HEADER_MAX]u8 = undefined;
    const hb_len = fmt.marshal(&h, &hb);

    var cipher = tf.Threefish.init(h.variant, enc_key, &h.tweak);
    var ctr = cipher.newCtr(h.ivSlice());

    const cs = h.chunk_size;
    const ct = try allocator.alloc(u8, cs);
    defer allocator.free(ct);
    const aad = try allocator.alloc(u8, 8 + hb_len + 13 + cs);
    defer allocator.free(aad);

    var index: u64 = 0;
    while (true) {
        var head: [5]u8 = undefined;
        const got = readSome(r, &head);
        if (got == 0) return Error.Truncated;
        if (got < 5) return Error.Truncated;
        if (head[0] > 1) return Error.BadContainer;
        const is_last = head[0] == 1;
        const ct_len = mem.readInt(u32, head[1..5], .big);
        if (ct_len > cs) return Error.BadContainer;
        if (!r.readFull(ct[0..ct_len])) return Error.Truncated;
        var tag: [32]u8 = undefined;
        if (!r.readFull(&tag)) return Error.Truncated;
        const aad_len = buildAad(aad, hb[0..hb_len], index, is_last, ct[0..ct_len]);
        if (!mac_mod.verify(h.mac, mac_key, aad[0..aad_len], &tag)) return Error.AuthFailed;
        ctr.apply(ct[0..ct_len]);
        if (ct_len > 0) try w.write(ct[0..ct_len]);
        if (is_last) break;
        if (ct_len != cs) return Error.BadContainer;
        index += 1;
    }
}

pub fn rawCtrStream(variant: Variant, key: []const u8, tweak: []const u8, iv: []const u8, allocator: mem.Allocator, r: Reader, w: Writer) Error!void {
    const bl = variant.keyLen();
    var cipher = tf.Threefish.init(variant, key, tweak);
    var ctr = cipher.newCtr(iv);
    const bufsz = (65536 / bl) * bl;
    const buf = try allocator.alloc(u8, bufsz);
    defer allocator.free(buf);
    while (true) {
        const n = readSome(r, buf);
        if (n == 0) break;
        ctr.apply(buf[0..n]);
        try w.write(buf[0..n]);
        if (n < bufsz) break;
    }
}

pub fn inspectStream(r: Reader, info: *ContainerInfo) Error!void {
    var h: Header = undefined;
    try fmt.read(r, &h);
    info.version = h.version;
    info.variant = h.variant;
    info.mac = h.mac;
    info.kdf = h.kdf;
    info.chunk_size = h.chunk_size;
    info.salt_len = h.salt_len;
    info.tweak = h.tweak;
    @memcpy(info.label[0..h.label_len], h.labelSlice());
    info.label_len = h.label_len;
}

// ---- slice convenience wrappers (over a fixed buffer / arraylist) ----

const SliceReader = struct {
    data: []const u8,
    pos: usize = 0,

    fn read(ctx: *anyopaque, buf: []u8) usize {
        const self: *SliceReader = @ptrCast(@alignCast(ctx));
        const n = @min(buf.len, self.data.len - self.pos);
        @memcpy(buf[0..n], self.data[self.pos .. self.pos + n]);
        self.pos += n;
        return n;
    }

    fn reader(self: *SliceReader) Reader {
        return .{ .ctx = self, .readFn = read };
    }
};

const ListWriter = struct {
    list: *std.ArrayList(u8),
    allocator: mem.Allocator,
    ok: bool = true,

    fn write(ctx: *anyopaque, bytes: []const u8) bool {
        const self: *ListWriter = @ptrCast(@alignCast(ctx));
        self.list.appendSlice(self.allocator, bytes) catch {
            self.ok = false;
            return false;
        };
        return true;
    }

    fn writer(self: *ListWriter) Writer {
        return .{ .ctx = self, .writeFn = write };
    }
};

/// Encrypt plaintext into a freshly-allocated container (caller frees).
pub fn encrypt(allocator: mem.Allocator, io: std.Io, password: []const u8, opts: Options, plaintext: []const u8) Error![]u8 {
    var sr = SliceReader{ .data = plaintext };
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    var lw = ListWriter{ .list = &list, .allocator = allocator };
    try encryptStream(allocator, io, password, opts, sr.reader(), lw.writer());
    return list.toOwnedSlice(allocator);
}

/// Decrypt a container into a freshly-allocated buffer (caller frees).
pub fn decrypt(allocator: mem.Allocator, io: std.Io, password: []const u8, expected_label: ?[]const u8, data: []const u8) Error![]u8 {
    var sr = SliceReader{ .data = data };
    var list: std.ArrayList(u8) = .empty;
    errdefer list.deinit(allocator);
    var lw = ListWriter{ .list = &list, .allocator = allocator };
    try decryptStream(allocator, io, password, expected_label, sr.reader(), lw.writer());
    return list.toOwnedSlice(allocator);
}

pub fn inspect(data: []const u8, info: *ContainerInfo) Error!void {
    var sr = SliceReader{ .data = data };
    try inspectStream(sr.reader(), info);
}
