//! The from-scratch primitives only (Threefish + CTR, Skein-512, BLAKE3), with no
//! allocator and no OS dependency. This is the root module for the bare-metal
//! `zig build freestanding` target, mirroring the Rust port's `no_std` cipher
//! crate: the cipher is portable to a freestanding target, the engine (whose KDFs
//! need an allocator) is not.

pub const threefish = @import("threefish.zig");
pub const skein = @import("skein.zig");
pub const blake3 = @import("blake3.zig");

comptime {
    _ = threefish;
    _ = skein;
    _ = blake3;
}
