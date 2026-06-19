#![no_main]

//! Fuzz the password-container decryptor against arbitrary input. It parses an
//! untrusted header and a sequence of authenticated frames, so it must never
//! panic, hang, or over-allocate on malformed bytes; it may only return an error
//! (or, vanishingly unlikely, succeed). This exercises `Header::read`, the frame
//! reader, the chunk-size and KDF-cost bounds, and MAC verification.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = dorado_engine::decrypt_password_bytes(b"fuzz-password", data);
});
