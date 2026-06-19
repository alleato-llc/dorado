//! The cryptographic construction over the `dorado` cipher, shared by the CLI
//! and GUI frontends: raw-key CTR and the authenticated, chunked password
//! container.
//!
//! It is decoupled from any UI. Streaming functions work over `Read`/`Write`
//! (used by the CLI for constant-memory file handling); in-memory wrappers
//! return `Vec<u8>` (used by the GUI). The cipher itself lives in the `dorado`
//! crate.

#![forbid(unsafe_code)]

mod format;
mod kdf;
mod mac;

use std::io::{Cursor, Read, Write};

use rand::RngCore;
use zeroize::Zeroizing;

use dorado::{Threefish1024, Threefish256, Threefish512};

use crate::format::{Header, MacId};
use crate::kdf::{derive, validate};

// Types the frontends need to build options and labels.
pub use crate::format::Variant;
pub use crate::kdf::{KdfParams, PrfId};

/// Domain separator mixed into every frame tag.
const FRAME_DOMAIN: &[u8; 8] = b"DRDOchnk";
/// Default authenticated chunk size for password encryption.
pub const DEFAULT_CHUNK_BYTES: u32 = 64 * 1024;
/// Upper bound on the header's chunk-size field, to bound per-frame allocation.
pub const MAX_CHUNK_BYTES: u32 = 1 << 30;
/// I/O buffer size for the unauthenticated raw-key streaming path.
const RAW_BUF_BYTES: usize = 64 * 1024;

/// Parameters for password encryption. Decryption reads them from the header.
#[derive(Clone)]
pub struct PasswordOptions {
    pub variant: Variant,
    pub kdf: KdfParams,
    pub tweak: [u8; 16],
    pub chunk_size: u32,
}

impl Default for PasswordOptions {
    fn default() -> Self {
        Self {
            variant: Variant::T256,
            kdf: KdfParams::Argon2id {
                m_cost: 64 * 1024,
                t_cost: 3,
                p_cost: 1,
            },
            tweak: [0u8; 16],
            chunk_size: DEFAULT_CHUNK_BYTES,
        }
    }
}

// ---------------------------------------------------------------------------
// Password container (authenticated, chunked, streamable).
// ---------------------------------------------------------------------------

/// Encrypt `reader` into `writer` as an authenticated password container.
pub fn encrypt_password_stream(
    password: &[u8],
    opts: &PasswordOptions,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), String> {
    let variant = opts.variant;
    let mut rng = rand::thread_rng();
    let mut salt = vec![0u8; 16];
    let mut iv = vec![0u8; variant.block_len()];
    rng.fill_bytes(&mut salt);
    rng.fill_bytes(&mut iv);

    // Derive an encryption key and a separate MAC key from one KDF output.
    let mut keymat = Zeroizing::new(vec![0u8; variant.key_len() + mac::KEY_LEN]);
    derive(&opts.kdf, password, &salt, &mut keymat)?;
    let (enc_key, mac_key) = keymat.split_at(variant.key_len());

    let header = Header {
        variant,
        kdf: opts.kdf,
        mac: MacId::HmacSha256,
        chunk_size: opts.chunk_size,
        salt,
        tweak: opts.tweak,
        iv,
    };
    let header_bytes = header.to_bytes();
    let cipher = Cipher::new(variant, enc_key, &opts.tweak)?;
    let blocks_per_chunk = (opts.chunk_size as usize / variant.block_len()) as u64;

    writer.write_all(&header_bytes).map_err(|e| e.to_string())?;

    // Read one chunk ahead so each chunk knows whether it is the last (which is
    // authenticated, defeating truncation).
    let mut counter = header.iv.clone();
    let mut index: u64 = 0;
    let mut current = vec![0u8; opts.chunk_size as usize];
    let mut n = read_fill(reader, &mut current).map_err(|e| e.to_string())?;
    loop {
        let mut next = vec![0u8; opts.chunk_size as usize];
        let next_n = read_fill(reader, &mut next).map_err(|e| e.to_string())?;
        let is_last = next_n == 0;

        let mut chunk = current[..n].to_vec();
        cipher.ctr_apply(&counter, &mut chunk)?;
        let tag = mac::tag(
            MacId::HmacSha256,
            mac_key,
            &frame_aad(&header_bytes, index, is_last, &chunk),
        );
        write_frame(writer, is_last, &chunk, &tag).map_err(|e| e.to_string())?;

        if is_last {
            break;
        }
        advance_counter(&mut counter, blocks_per_chunk);
        index += 1;
        current = next;
        n = next_n;
    }
    writer.flush().map_err(|e| e.to_string())
}

/// Decrypt an authenticated password container from `reader` into `writer`.
pub fn decrypt_password_stream(
    password: &[u8],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), String> {
    let header = Header::read(reader)?;
    let header_bytes = header.to_bytes();
    let block_len = header.variant.block_len();
    if header.chunk_size == 0
        || header.chunk_size > MAX_CHUNK_BYTES
        || !(header.chunk_size as usize).is_multiple_of(block_len)
    {
        return Err(format!(
            "invalid chunk size {} in header",
            header.chunk_size
        ));
    }
    // Bound the cost before deriving: the params come from an untrusted header.
    validate(&header.kdf)?;

    let mut keymat = Zeroizing::new(vec![0u8; header.variant.key_len() + mac::KEY_LEN]);
    derive(&header.kdf, password, &header.salt, &mut keymat)?;
    let (enc_key, mac_key) = keymat.split_at(header.variant.key_len());
    let cipher = Cipher::new(header.variant, enc_key, &header.tweak)?;
    let blocks_per_chunk = (header.chunk_size as usize / block_len) as u64;

    let mut counter = header.iv.clone();
    let mut index: u64 = 0;
    loop {
        let frame = read_frame(reader, header.chunk_size)?;
        // Verify each frame (which also rejects a wrong password) before decrypting.
        mac::verify(
            header.mac,
            mac_key,
            &frame_aad(&header_bytes, index, frame.is_last, &frame.ciphertext),
            &frame.tag,
        )?;

        let mut chunk = frame.ciphertext;
        cipher.ctr_apply(&counter, &mut chunk)?;
        writer.write_all(&chunk).map_err(|e| e.to_string())?;

        if frame.is_last {
            break;
        }
        if chunk.len() != header.chunk_size as usize {
            return Err("non-final chunk is not full size".into());
        }
        advance_counter(&mut counter, blocks_per_chunk);
        index += 1;
    }
    writer.flush().map_err(|e| e.to_string())
}

/// In-memory convenience wrapper over [`encrypt_password_stream`].
pub fn encrypt_password_bytes(
    password: &[u8],
    opts: &PasswordOptions,
    plaintext: &[u8],
) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut reader = Cursor::new(plaintext);
    encrypt_password_stream(password, opts, &mut reader, &mut out)?;
    Ok(out)
}

/// In-memory convenience wrapper over [`decrypt_password_stream`].
pub fn decrypt_password_bytes(password: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut reader = Cursor::new(data);
    decrypt_password_stream(password, &mut reader, &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Raw-key CTR (bare, unauthenticated).
// ---------------------------------------------------------------------------

/// Stream bare CTR with a user-supplied key and IV (no header, no authentication).
/// Encrypt and decrypt are the same operation.
pub fn raw_ctr_stream(
    variant: Variant,
    key: &[u8],
    tweak: &[u8; 16],
    iv: &[u8],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<(), String> {
    let block_len = variant.block_len();
    let cipher = Cipher::new(variant, key, tweak)?;
    let buf_blocks = (RAW_BUF_BYTES / block_len).max(1);
    let buf_len = buf_blocks * block_len;

    let mut counter = iv.to_vec();
    let mut buf = vec![0u8; buf_len];
    loop {
        let n = read_fill(reader, &mut buf).map_err(|e| e.to_string())?;
        if n == 0 {
            break;
        }
        cipher.ctr_apply(&counter, &mut buf[..n])?;
        writer.write_all(&buf[..n]).map_err(|e| e.to_string())?;
        advance_counter(&mut counter, n.div_ceil(block_len) as u64);
        if n < buf_len {
            break;
        }
    }
    writer.flush().map_err(|e| e.to_string())
}

// ---------------------------------------------------------------------------
// Single-block cipher (for demos): encrypt or decrypt exactly one block.
// ---------------------------------------------------------------------------

/// Encrypt (or decrypt) exactly one block. The variant is inferred from the key
/// length, and `block` must be that block size.
pub fn block_transform(
    key: &[u8],
    tweak: &[u8; 16],
    block: &[u8],
    decrypt: bool,
) -> Result<Vec<u8>, String> {
    let variant = variant_from_key_len(key.len())?;
    if block.len() != variant.block_len() {
        return Err(format!(
            "block must be {} bytes for this key, got {}",
            variant.block_len(),
            block.len()
        ));
    }
    let mut out = block.to_vec();
    match variant {
        Variant::T256 => {
            let c = Threefish256::new(&fixed(key)?, tweak);
            let b: &mut [u8; 32] = (&mut out[..]).try_into().unwrap();
            if decrypt {
                c.decrypt_block(b)
            } else {
                c.encrypt_block(b)
            }
        }
        Variant::T512 => {
            let c = Threefish512::new(&fixed(key)?, tweak);
            let b: &mut [u8; 64] = (&mut out[..]).try_into().unwrap();
            if decrypt {
                c.decrypt_block(b)
            } else {
                c.encrypt_block(b)
            }
        }
        Variant::T1024 => {
            let c = Threefish1024::new(&fixed(key)?, tweak);
            let b: &mut [u8; 128] = (&mut out[..]).try_into().unwrap();
            if decrypt {
                c.decrypt_block(b)
            } else {
                c.encrypt_block(b)
            }
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Shared helpers.
// ---------------------------------------------------------------------------

/// A Threefish variant with its key schedule built once, for reuse across the
/// many CTR calls of a streaming pass.
enum Cipher {
    T256(Threefish256),
    T512(Threefish512),
    T1024(Threefish1024),
}

impl Cipher {
    fn new(variant: Variant, key: &[u8], tweak: &[u8; 16]) -> Result<Self, String> {
        Ok(match variant {
            Variant::T256 => Cipher::T256(Threefish256::new(&fixed(key)?, tweak)),
            Variant::T512 => Cipher::T512(Threefish512::new(&fixed(key)?, tweak)),
            Variant::T1024 => Cipher::T1024(Threefish1024::new(&fixed(key)?, tweak)),
        })
    }

    fn ctr_apply(&self, iv: &[u8], data: &mut [u8]) -> Result<(), String> {
        match self {
            Cipher::T256(c) => c.ctr_apply(&fixed(iv)?, data),
            Cipher::T512(c) => c.ctr_apply(&fixed(iv)?, data),
            Cipher::T1024(c) => c.ctr_apply(&fixed(iv)?, data),
        }
        Ok(())
    }
}

/// Copy a slice of the statically expected length into a fixed-size array.
fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N], String> {
    bytes
        .try_into()
        .map_err(|_| format!("expected {N} bytes, got {}", bytes.len()))
}

/// One parsed frame from the stream.
struct Frame {
    is_last: bool,
    ciphertext: Vec<u8>,
    tag: [u8; mac::TAG_LEN],
}

/// Authenticated data for a frame: a domain separator, the whole header (for the
/// first frame only, binding the parameters), the frame index, the last flag,
/// and the ciphertext. The index and flag defeat reordering, dropping, and
/// truncation; the header binding defeats parameter tampering.
fn frame_aad(header_bytes: &[u8], index: u64, is_last: bool, ciphertext: &[u8]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ciphertext.len() + 64);
    aad.extend_from_slice(FRAME_DOMAIN);
    if index == 0 {
        aad.extend_from_slice(header_bytes);
    }
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(is_last as u8);
    aad.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    aad.extend_from_slice(ciphertext);
    aad
}

/// Write one frame: last flag, ciphertext length, ciphertext, tag.
fn write_frame(
    w: &mut dyn Write,
    is_last: bool,
    ciphertext: &[u8],
    tag: &[u8],
) -> std::io::Result<()> {
    w.write_all(&[is_last as u8])?;
    w.write_all(&(ciphertext.len() as u32).to_be_bytes())?;
    w.write_all(ciphertext)?;
    w.write_all(tag)
}

/// Read one frame, bounding the ciphertext length by the header's chunk size.
fn read_frame(r: &mut dyn Read, chunk_size: u32) -> Result<Frame, String> {
    let mut head = [0u8; 5];
    let n = read_fill(r, &mut head).map_err(|e| e.to_string())?;
    if n == 0 {
        return Err("stream ended before the final chunk (truncated)".into());
    }
    if n < head.len() {
        return Err("incomplete frame header (truncated)".into());
    }
    let is_last = match head[0] {
        0 => false,
        1 => true,
        other => return Err(format!("invalid frame flag {other}")),
    };
    let ct_len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
    if ct_len > chunk_size {
        return Err("frame length exceeds the header chunk size".into());
    }
    let mut ciphertext = vec![0u8; ct_len as usize];
    if read_fill(r, &mut ciphertext).map_err(|e| e.to_string())? != ct_len as usize {
        return Err("truncated frame ciphertext".into());
    }
    let mut tag = [0u8; mac::TAG_LEN];
    if read_fill(r, &mut tag).map_err(|e| e.to_string())? != mac::TAG_LEN {
        return Err("truncated frame tag".into());
    }
    Ok(Frame {
        is_last,
        ciphertext,
        tag,
    })
}

/// Add `blocks` to the big-endian counter `ctr` in place, wrapping on overflow.
/// The counter is public, so no constant-time discipline is needed here.
pub fn advance_counter(ctr: &mut [u8], blocks: u64) {
    let add = blocks.to_be_bytes();
    let mut carry = 0u16;
    for i in 0..ctr.len() {
        let ci = ctr.len() - 1 - i;
        let ai = if i < add.len() {
            add[add.len() - 1 - i] as u16
        } else {
            0
        };
        let sum = ctr[ci] as u16 + ai + carry;
        ctr[ci] = sum as u8;
        carry = sum >> 8;
        if i >= add.len() && carry == 0 {
            break;
        }
    }
}

/// Read up to `buf.len()` bytes, returning how many were read (a short count
/// means end of input).
fn read_fill(r: &mut dyn Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        let n = r.read(&mut buf[filled..])?;
        if n == 0 {
            break;
        }
        filled += n;
    }
    Ok(filled)
}

/// Map a key length to its variant.
pub fn variant_from_key_len(n: usize) -> Result<Variant, String> {
    match n {
        32 => Ok(Variant::T256),
        64 => Ok(Variant::T512),
        128 => Ok(Variant::T1024),
        n => Err(format!("key must be 32, 64, or 128 bytes, got {n}")),
    }
}

/// Parse a hex string (ignoring whitespace) into bytes.
pub fn parse_hex(s: &str) -> Result<Vec<u8>, String> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err("odd number of hex digits".into());
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| format!("invalid hex at byte {}", i / 2))
        })
        .collect()
}

/// Parse a 16-byte tweak from hex.
pub fn parse_tweak(s: &str) -> Result<[u8; 16], String> {
    let t = parse_hex(s).map_err(|e| format!("tweak: {e}"))?;
    if t.len() != 16 {
        return Err(format!("tweak must be 16 bytes, got {}", t.len()));
    }
    Ok(t.try_into().unwrap())
}

#[cfg(test)]
mod tests;
