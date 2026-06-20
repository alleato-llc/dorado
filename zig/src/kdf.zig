//! The three key-derivation functions, from Zig's standard library
//! (`std.crypto.pwhash`): Argon2id, scrypt, and PBKDF2-HMAC-SHA256. These are
//! standard algorithms, so the derived keys match the Rust reference byte-for-byte.
//! Unlike the other ports, no external library is needed.

const std = @import("std");
const argon2 = std.crypto.pwhash.argon2;
const scrypt = std.crypto.pwhash.scrypt;
const pbkdf2_fn = std.crypto.pwhash.pbkdf2;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const fmt = @import("format.zig");

pub const Error = error{
    OutOfMemory,
    KdfFailed,
    HostileCost,
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

/// Reject KDF parameters whose cost is unreasonably large. The cost comes from an
/// untrusted header. Bounds match the other ports.
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
            if (p.rounds > 50_000_000) return Error.HostileCost;
        },
    }
}
