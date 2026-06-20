//! The MAC menu: Skein-512 (default) and keyed BLAKE3 from this project's
//! from-scratch hashes, HMAC-SHA256 from Zig's standard library. All three take the
//! 32-byte MAC key and produce a 32-byte tag.

const std = @import("std");
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const fmt = @import("format.zig");
const skein = @import("skein.zig");
const blake3 = @import("blake3.zig");

/// Compute a 32-byte tag over signed_data under the selected MAC.
pub fn tag(mac: fmt.Mac, mac_key: *const [32]u8, signed_data: []const u8, out: *[32]u8) void {
    switch (mac) {
        .skein => skein.mac(mac_key, 32, signed_data, out),
        .blake3 => blake3.keyedMac(mac_key, signed_data, out),
        .hmac => HmacSha256.create(out, signed_data, mac_key),
    }
}

/// Recompute the tag and compare it in constant time.
pub fn verify(mac: fmt.Mac, mac_key: *const [32]u8, signed_data: []const u8, received: *const [32]u8) bool {
    var expected: [32]u8 = undefined;
    tag(mac, mac_key, signed_data, &expected);
    return std.crypto.timing_safe.eql([32]u8, expected, received.*);
}
