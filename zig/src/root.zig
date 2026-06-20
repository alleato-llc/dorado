//! dorado: a from-scratch Threefish cipher and authenticated container (Zig port).
//!
//! Educational and unaudited; for real data prefer a vetted library. The on-disk
//! format is byte-for-byte cross-compatible with the Rust reference and the Go,
//! Java, Python, C, and TypeScript ports.

pub const threefish = @import("threefish.zig");
pub const skein = @import("skein.zig");
pub const blake3 = @import("blake3.zig");
pub const format = @import("format.zig");
pub const kdf = @import("kdf.zig");
pub const mac = @import("mac.zig");
pub const engine = @import("engine.zig");

pub const Variant = threefish.Variant;
pub const Kdf = format.Kdf;
pub const Mac = format.Mac;
pub const Options = engine.Options;
pub const ContainerInfo = engine.ContainerInfo;
pub const Error = engine.Error;

test {
    @import("std").testing.refAllDecls(@This());
}
