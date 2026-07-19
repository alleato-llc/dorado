//! Key derivation, in its two standard forms.
//!
//! `derive` is password-based derivation (a PBKDF): it stretches a weak,
//! guessable secret into a raw key, deliberately slowly, under caller-tunable
//! cost parameters (`validate` bounds untrusted ones). The three algorithms
//! (Argon2id, scrypt, PBKDF2-HMAC-SHA256) come from Zig's standard library
//! (`std.crypto.pwhash`); they are standard, so the derived keys match the
//! Rust reference byte-for-byte. Unlike the other ports, no external library
//! is needed.
//!
//! `deriveFromKey` is key-based derivation (a KBKDF): it splits an already
//! high-entropy key into independent, domain-separated children, fast (one
//! keyed hash), with no salt and no cost parameters because there is nothing
//! to stretch. The keyed hash defaults to Skein-512 (Threefish's native
//! companion); `deriveFromKeyWith` lets a caller pick the PRF (`KdfPrf`)
//! instead, e.g. BLAKE3 to keep a ChaCha-family construction single-family
//! top to bottom. Both use this port's own from-scratch primitives, not
//! `std.crypto`. The names are the guardrail: a password must never take the
//! fast path, and a key never needs the slow one.

const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;
const scrypt = std.crypto.pwhash.scrypt;
const pbkdf2_fn = std.crypto.pwhash.pbkdf2;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const fmt = @import("format.zig");
const skein = @import("skein.zig");
const blake3 = @import("blake3.zig");

pub const Error = error{
    OutOfMemory,
    KdfFailed,
    HostileCost,
    BadKeyLength,
};

/// Stretch password (with salt) into out using params.
pub fn derive(
    allocator: std.mem.Allocator,
    io: std.Io,
    kdf: fmt.Kdf,
    password: []const u8,
    salt: []const u8,
    out: []u8,
) Error!void {
    switch (kdf) {
        .argon2id => |a| {
            argon2.kdf(
                allocator,
                out,
                password,
                salt,
                .{ .t = a.t_cost, .m = a.m_cost, .p = @intCast(a.p_cost) },
                .argon2id,
                io,
            ) catch return Error.KdfFailed;
        },
        .scrypt => |s| {
            scrypt.kdf(
                allocator,
                out,
                password,
                salt,
                .{ .ln = @intCast(s.log_n), .r = @intCast(s.r), .p = @intCast(s.p) },
            ) catch return Error.KdfFailed;
        },
        .pbkdf2 => |p| {
            pbkdf2_fn(out, password, salt, p.rounds, HmacSha256) catch return Error.KdfFailed;
        },
    }
}

/// The keyed hash `deriveFromKeyWith` fans a master key out with. Both are
/// secure PRFs and produce identically strong children; the choice exists only
/// to let a construction stay within one cryptographic family (Skein for
/// Threefish, BLAKE3 for a ChaCha-family cipher) rather than mixing lineages.
pub const KdfPrf = enum {
    /// Skein-512 keyed hash (Threefish's native companion). The default, and
    /// what `deriveFromKey` uses. Accepts a key of any length.
    skein512,
    /// BLAKE3 keyed hash. Requires a 32-byte key (BLAKE3's keyed mode is
    /// defined only for a 256-bit key); other lengths are `Error.BadKeyLength`.
    blake3,
};

/// Fixed prefix domain-separating `deriveFromKey`'s keyed hashing from every
/// other keyed use in the engine (`DRDOrawE`/`DRDOrawM` in the raw-key split,
/// `DRDOchnk`/`DRDOrwFr` in the frame MACs).
const DERIVE_FROM_KEY_DOMAIN = "DRDOkdrv";

/// Derive `out.len` key bytes from an already high-entropy `key`, separated by
/// `domain` -- key-based derivation (the fast form): one domain-separated
/// Skein-512 keyed hash, no salt, no cost parameters, because a strong key has
/// nothing to stretch. Deterministic: the same key and domain always yield the
/// same bytes, and different domains yield computationally unrelated ones, so a
/// caller can fan one master key out into independent per-purpose keys
/// (`deriveFromKey(master, "myapp/index", ..)`,
/// `deriveFromKey(master, "myapp/data", ..)`). Never pass a password here:
/// there is no stretching, so a guessable input stays guessable -- that is
/// `derive`'s job. To fan out with a different PRF (e.g. BLAKE3), use
/// `deriveFromKeyWith`.
pub fn deriveFromKey(key: []const u8, domain: []const u8, out: []u8) void {
    deriveFromKeyWith(.skein512, key, domain, out) catch unreachable;
}

/// `deriveFromKey` with a caller-chosen PRF (`KdfPrf`). The domain separation,
/// determinism, and "never pass a password" contract are exactly the same;
/// only the underlying keyed hash changes. With `.skein512` this is
/// byte-for-byte identical to `deriveFromKey`. `.blake3` requires `key` to be
/// 32 bytes and returns `Error.BadKeyLength` otherwise.
pub fn deriveFromKeyWith(prf: KdfPrf, key: []const u8, domain: []const u8, out: []u8) Error!void {
    switch (prf) {
        .skein512 => {
            // Streaming update(A) then update(B) equals update(A ++ B), so
            // this matches a one-shot MAC over the concatenated message.
            var h = skein.Skein512.initMac(key, out.len);
            h.update(DERIVE_FROM_KEY_DOMAIN);
            h.update(domain);
            h.finalize(out);
        },
        .blake3 => {
            if (key.len != 32) return Error.BadKeyLength;
            var h = blake3.Hasher.initKeyed(key[0..32]);
            h.update(DERIVE_FROM_KEY_DOMAIN);
            h.update(domain);
            h.finalize(out);
        },
    }
}

/// Reject KDF parameters whose cost is unreasonably large (the cost comes from
/// an untrusted header) or nonsensical (zero PBKDF2 rounds). Bounds match the
/// other ports.
pub fn validate(kdf: fmt.Kdf) Error!void {
    switch (kdf) {
        .argon2id => |a| {
            if (a.m_cost > (1 << 21)) return Error.HostileCost;
            if (a.t_cost > 64) return Error.HostileCost;
            if (a.p_cost > 16) return Error.HostileCost;
        },
        .scrypt => |s| {
            if (s.log_n > 21) return Error.HostileCost;
            if (s.r > 32) return Error.HostileCost;
            if (s.p > 16) return Error.HostileCost;
        },
        .pbkdf2 => |p| {
            // Zero rounds would "derive" an all-zero key without error.
            if (p.rounds == 0) return Error.HostileCost;
            if (p.rounds > 50_000_000) return Error.HostileCost;
        },
    }
}
