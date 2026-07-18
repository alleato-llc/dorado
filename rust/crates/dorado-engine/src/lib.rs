//! The cryptographic construction over the `dorado` cipher, shared by the CLI
//! and GUI frontends: raw-key CTR and the authenticated, chunked password
//! container.
//!
//! It is decoupled from any UI. Streaming functions work over `Read`/`Write`
//! (used by the CLI for constant-memory file handling); in-memory wrappers
//! return `Vec<u8>` (used by the GUI). The cipher itself lives in the `dorado`
//! crate.

#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod error;
mod format;
mod kdf;
mod mac;

use std::io::{Cursor, Read, Write};

use rand::RngCore;
use zeroize::Zeroizing;

use dorado::{Threefish1024, Threefish256, Threefish512};

pub use crate::error::{Error, Result};
use crate::format::Header;
use crate::kdf::{derive, validate};

// Types the frontends need to build options and labels.
pub use crate::format::{MacId, Variant};
pub use crate::kdf::{KdfParams, PrfId};

/// Domain separator mixed into every frame tag.
const FRAME_DOMAIN: &[u8; 8] = b"DRDOchnk";
/// Default authenticated chunk size for password encryption.
pub const DEFAULT_CHUNK_BYTES: u32 = 64 * 1024;
/// Hard ceiling on the accepted chunk size, regardless of any override, bounding
/// per-frame allocation when reading an untrusted header. 1 GiB.
pub const MAX_CHUNK_BYTES: u32 = 1 << 30;
/// Default cap on the header's chunk-size field when `DORADO_MAX_CHUNK_BYTES` is not
/// set. Normal files use `DEFAULT_CHUNK_BYTES` (64 KiB), far below this, so the cap
/// only ever rejects a hostile or absurd header. 64 MiB.
pub const DEFAULT_MAX_CHUNK_BYTES: u32 = 64 * 1024 * 1024;
/// The container format version this build reads and writes.
pub const FORMAT_VERSION: u8 = format::VERSION;
/// I/O buffer size for the unauthenticated raw-key streaming path.
const RAW_BUF_BYTES: usize = 64 * 1024;

/// Parameters for password encryption. Decryption reads them from the header.
#[derive(Clone)]
pub struct PasswordOptions {
    /// Threefish block size to use.
    pub variant: Variant,
    /// KDF and its cost parameters.
    pub kdf: KdfParams,
    /// MAC that authenticates each chunk.
    pub mac: MacId,
    /// The 16-byte tweak (non-secret).
    pub tweak: [u8; 16],
    /// Plaintext bytes per authenticated chunk.
    pub chunk_size: u32,
    /// Optional non-secret label, stored in the header and authenticated. Empty
    /// for no label. Decryption can require a matching label (see
    /// [`decrypt_password_stream_expecting`]).
    pub label: Vec<u8>,
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
            // Skein-512: the Threefish-native MAC, so the default construction
            // stays entirely within the Threefish family.
            mac: MacId::Skein512,
            tweak: [0u8; 16],
            chunk_size: DEFAULT_CHUNK_BYTES,
            label: Vec::new(),
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
) -> Result<()> {
    let variant = opts.variant;
    let mut salt = vec![0u8; 16];
    let mut iv = vec![0u8; variant.block_len()];
    fill_random(&mut salt)?;
    fill_random(&mut iv)?;

    // Derive an encryption key and a separate MAC key from one KDF output.
    let mut keymat = Zeroizing::new(vec![0u8; variant.key_len() + mac::KEY_LEN]);
    derive(&opts.kdf, password, &salt, &mut keymat)?;
    let (enc_key, mac_key) = keymat.split_at(variant.key_len());

    if opts.label.len() > format::MAX_LABEL_LEN {
        return Err(Error::InvalidParams(format!(
            "label too long ({} bytes, max {})",
            opts.label.len(),
            format::MAX_LABEL_LEN
        )));
    }
    let header = Header {
        version: format::VERSION,
        variant,
        kdf: opts.kdf,
        mac: opts.mac,
        chunk_size: opts.chunk_size,
        salt,
        tweak: opts.tweak,
        iv,
        label: opts.label.clone(),
    };
    let header_bytes = header.to_bytes();
    let cipher = Cipher::new(variant, enc_key, &opts.tweak)?;
    let blocks_per_chunk = (opts.chunk_size as usize / variant.block_len()) as u64;

    writer.write_all(&header_bytes)?;

    // Read one chunk ahead so each chunk knows whether it is the last (which is
    // authenticated, defeating truncation).
    let mut counter = header.iv.clone();
    let mut index: u64 = 0;
    let mut current = vec![0u8; opts.chunk_size as usize];
    let mut n = read_fill(reader, &mut current)?;
    loop {
        let mut next = vec![0u8; opts.chunk_size as usize];
        let next_n = read_fill(reader, &mut next)?;
        let is_last = next_n == 0;

        let mut chunk = current[..n].to_vec();
        cipher.ctr_apply(&counter, &mut chunk)?;
        let tag = mac::tag(
            opts.mac,
            mac_key,
            &frame_aad(&header_bytes, index, is_last, &chunk),
        );
        write_frame(writer, is_last, &chunk, &tag)?;

        if is_last {
            break;
        }
        advance_counter(&mut counter, blocks_per_chunk);
        index += 1;
        current = next;
        n = next_n;
    }
    writer.flush().map_err(Error::from)
}

/// Decrypt an authenticated password container from `reader` into `writer`.
pub fn decrypt_password_stream(
    password: &[u8],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<()> {
    decrypt_password_stream_expecting(password, None, reader, writer)
}

/// Like [`decrypt_password_stream`], but if `expected_label` is `Some`, the
/// container's stored label must equal it or decryption fails before any
/// plaintext is written. Use this to bind a file to a known name or context and
/// detect a substituted (but otherwise valid) file. The label is authenticated,
/// so a mismatch cannot be forged.
pub fn decrypt_password_stream_expecting(
    password: &[u8],
    expected_label: Option<&[u8]>,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<()> {
    let header = Header::read(reader)?;
    if let Some(expected) = expected_label {
        if expected != header.label.as_slice() {
            return Err(Error::InvalidParams(
                "container label does not match the expected label".into(),
            ));
        }
    }
    let header_bytes = header.to_bytes();
    let block_len = header.variant.block_len();
    if header.chunk_size == 0
        || header.chunk_size > max_chunk_bytes()
        || !(header.chunk_size as usize).is_multiple_of(block_len)
    {
        return Err(Error::InvalidParams(format!(
            "invalid chunk size {} in header",
            header.chunk_size
        )));
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
        writer.write_all(&chunk)?;

        if frame.is_last {
            break;
        }
        if chunk.len() != header.chunk_size as usize {
            return Err(Error::MalformedHeader(
                "non-final chunk is not full size".into(),
            ));
        }
        advance_counter(&mut counter, blocks_per_chunk);
        index += 1;
    }
    writer.flush().map_err(Error::from)
}

/// In-memory convenience wrapper over [`encrypt_password_stream`].
///
/// # Example
///
/// ```
/// use dorado_engine::{
///     encrypt_password_bytes, decrypt_password_bytes, KdfParams, PasswordOptions, PrfId,
/// };
///
/// // PBKDF2 with a low round count keeps this example fast; real use wants more.
/// let opts = PasswordOptions {
///     kdf: KdfParams::Pbkdf2 { rounds: 1000, prf: PrfId::HmacSha256 },
///     ..Default::default()
/// };
///
/// let ct = encrypt_password_bytes(b"hunter2", &opts, b"secret").unwrap();
/// assert_eq!(decrypt_password_bytes(b"hunter2", &ct).unwrap(), b"secret");
/// assert!(decrypt_password_bytes(b"wrong", &ct).is_err());
/// ```
pub fn encrypt_password_bytes(
    password: &[u8],
    opts: &PasswordOptions,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut reader = Cursor::new(plaintext);
    encrypt_password_stream(password, opts, &mut reader, &mut out)?;
    Ok(out)
}

/// In-memory convenience wrapper over [`decrypt_password_stream`].
pub fn decrypt_password_bytes(password: &[u8], data: &[u8]) -> Result<Vec<u8>> {
    decrypt_password_bytes_expecting(password, None, data)
}

/// In-memory convenience wrapper over [`decrypt_password_stream_expecting`].
pub fn decrypt_password_bytes_expecting(
    password: &[u8],
    expected_label: Option<&[u8]>,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut reader = Cursor::new(data);
    decrypt_password_stream_expecting(password, expected_label, &mut reader, &mut out)?;
    Ok(out)
}

/// The non-secret parameters of a password container, as read from its header.
/// Every field here is stored in the clear in the file, so reporting it reveals
/// nothing the file does not already disclose.
#[derive(Debug, Clone)]
pub struct ContainerInfo {
    /// On-disk format version of the file.
    pub version: u8,
    /// Threefish block size the file uses.
    pub variant: Variant,
    /// KDF and its cost parameters.
    pub kdf: KdfParams,
    /// MAC that authenticates each chunk.
    pub mac: MacId,
    /// Plaintext bytes per authenticated chunk.
    pub chunk_size: u32,
    /// Length of the random salt, in bytes.
    pub salt_len: usize,
    /// The 16-byte tweak (non-secret).
    pub tweak: [u8; 16],
    /// The non-secret label, empty if none (version 4+).
    pub label: Vec<u8>,
}

/// Read and describe a password container's header without decrypting it (and
/// without a password). Only the header bytes are consumed from `reader`.
pub fn inspect(reader: &mut dyn Read) -> Result<ContainerInfo> {
    let header = Header::read(reader)?;
    Ok(ContainerInfo {
        version: header.version,
        variant: header.variant,
        kdf: header.kdf,
        mac: header.mac,
        chunk_size: header.chunk_size,
        salt_len: header.salt.len(),
        tweak: header.tweak,
        label: header.label,
    })
}

/// In-memory convenience wrapper over [`inspect`].
pub fn inspect_bytes(data: &[u8]) -> Result<ContainerInfo> {
    inspect(&mut Cursor::new(data))
}

// ---------------------------------------------------------------------------
// Raw-key CTR (bare, unauthenticated).
// ---------------------------------------------------------------------------

/// Stream bare CTR with a user-supplied key and IV (no header, no authentication).
/// Encrypt and decrypt are the same operation.
///
/// This provides confidentiality only. A corrupted or tampered ciphertext byte
/// decrypts to a flipped plaintext byte at the same position, silently, with no
/// error of any kind — CTR mode has no way to detect this. If the caller needs
/// tamper/corruption detection, use [`encrypt_raw_authenticated_stream`] instead.
pub fn raw_ctr_stream(
    variant: Variant,
    key: &[u8],
    tweak: &[u8; 16],
    iv: &[u8],
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<()> {
    let block_len = variant.block_len();
    let cipher = Cipher::new(variant, key, tweak)?;
    let buf_blocks = (RAW_BUF_BYTES / block_len).max(1);
    let buf_len = buf_blocks * block_len;

    let mut counter = iv.to_vec();
    let mut buf = vec![0u8; buf_len];
    loop {
        let n = read_fill(reader, &mut buf)?;
        if n == 0 {
            break;
        }
        cipher.ctr_apply(&counter, &mut buf[..n])?;
        writer.write_all(&buf[..n])?;
        advance_counter(&mut counter, n.div_ceil(block_len) as u64);
        if n < buf_len {
            break;
        }
    }
    writer.flush().map_err(Error::from)
}

// ---------------------------------------------------------------------------
// Raw-key authenticated CTR (encrypt-then-MAC, caller-supplied key).
// ---------------------------------------------------------------------------

/// Domain separator for deriving the encryption subkey from a raw key.
const RAW_AUTH_ENC_DOMAIN: &[u8; 8] = b"DRDOrawE";
/// Domain separator for deriving the MAC subkey from a raw key.
const RAW_AUTH_MAC_DOMAIN: &[u8; 8] = b"DRDOrawM";
/// Domain separator mixed into every raw-authenticated frame tag. Distinct from
/// [`FRAME_DOMAIN`] so a raw-mode frame's tag can never collide with or be
/// replayed as a password-mode frame's tag, even under key reuse across both
/// paths.
const RAW_FRAME_DOMAIN: &[u8; 8] = b"DRDOrwFr";

/// Split a caller-supplied raw key into an independent encryption subkey and MAC
/// subkey, each derived via domain-separated Skein-512 keyed hashing (`key` is
/// the MAC key, the domain label is the message). This is deliberately not a
/// password KDF: `key` is assumed to already be high-entropy (e.g. from an OS
/// keychain or a CSPRNG), so no cost-parameterized stretching is needed, only
/// separation into two subkeys that must not be the same bytes used for two
/// different primitives.
fn split_raw_key(variant: Variant, key: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
    if key.len() != variant.key_len() {
        return Err(Error::InvalidParams(format!(
            "raw key must be {} bytes for this variant, got {}",
            variant.key_len(),
            key.len()
        )));
    }
    let mut keymat = Zeroizing::new(vec![0u8; variant.key_len() + mac::KEY_LEN]);
    let (enc_part, mac_part) = keymat.split_at_mut(variant.key_len());
    dorado::skein::mac_into(enc_part, key, RAW_AUTH_ENC_DOMAIN);
    dorado::skein::mac_into(mac_part, key, RAW_AUTH_MAC_DOMAIN);
    Ok(keymat)
}

/// Authenticated data for a raw-mode frame: a domain separator, the tweak and
/// IV (for the first frame only, binding the parameters — raw mode has no
/// header to bind them into the way the password container does), the frame
/// index, the last flag, and the ciphertext. Mirrors [`frame_aad`], substituting
/// tweak+IV for the header.
fn raw_frame_aad(
    tweak: &[u8; 16],
    iv: &[u8],
    index: u64,
    is_last: bool,
    ciphertext: &[u8],
) -> Vec<u8> {
    let mut aad = Vec::with_capacity(ciphertext.len() + 64);
    aad.extend_from_slice(RAW_FRAME_DOMAIN);
    if index == 0 {
        aad.extend_from_slice(tweak);
        aad.extend_from_slice(iv);
    }
    aad.extend_from_slice(&index.to_be_bytes());
    aad.push(is_last as u8);
    aad.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
    aad.extend_from_slice(ciphertext);
    aad
}

/// Validate the IV and chunk size shared by the raw-authenticated encrypt and
/// decrypt paths.
fn validate_raw_auth_params(variant: Variant, iv: &[u8], chunk_size: u32) -> Result<()> {
    if iv.len() != variant.block_len() {
        return Err(Error::InvalidParams(format!(
            "iv must be {} bytes for this variant, got {}",
            variant.block_len(),
            iv.len()
        )));
    }
    if chunk_size == 0 || !(chunk_size as usize).is_multiple_of(variant.block_len()) {
        return Err(Error::InvalidParams(format!(
            "chunk size must be a positive multiple of the block size ({}), got {chunk_size}",
            variant.block_len()
        )));
    }
    Ok(())
}

/// Stream authenticated CTR with a caller-supplied key: encrypt-then-MAC, no
/// password, no KDF (see [`split_raw_key`]). Data streams in fixed-size
/// authenticated chunks, reusing the same frame construction as the password
/// container (`frame_aad`/`write_frame`/`read_frame`), so truncation,
/// reordering, and dropped chunks are all rejected on decryption exactly as
/// they are there. There is no header: the caller must supply the same
/// `variant`, `tweak`, `iv`, `mac`, and `chunk_size` on decrypt as were used to
/// encrypt, and remember them out of band (nothing here is written to the
/// stream itself, matching [`raw_ctr_stream`]'s no-header philosophy).
#[allow(clippy::too_many_arguments)]
pub fn encrypt_raw_authenticated_stream(
    variant: Variant,
    key: &[u8],
    tweak: &[u8; 16],
    iv: &[u8],
    mac: MacId,
    chunk_size: u32,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<()> {
    validate_raw_auth_params(variant, iv, chunk_size)?;
    let keymat = split_raw_key(variant, key)?;
    let (enc_key, mac_key) = keymat.split_at(variant.key_len());
    let cipher = Cipher::new(variant, enc_key, tweak)?;
    let blocks_per_chunk = (chunk_size as usize / variant.block_len()) as u64;

    // Read one chunk ahead so each chunk knows whether it is the last (which is
    // authenticated, defeating truncation) — same shape as encrypt_password_stream.
    let mut counter = iv.to_vec();
    let mut index: u64 = 0;
    let mut current = vec![0u8; chunk_size as usize];
    let mut n = read_fill(reader, &mut current)?;
    loop {
        let mut next = vec![0u8; chunk_size as usize];
        let next_n = read_fill(reader, &mut next)?;
        let is_last = next_n == 0;

        let mut chunk = current[..n].to_vec();
        cipher.ctr_apply(&counter, &mut chunk)?;
        let tag = mac::tag(
            mac,
            mac_key,
            &raw_frame_aad(tweak, iv, index, is_last, &chunk),
        );
        write_frame(writer, is_last, &chunk, &tag)?;

        if is_last {
            break;
        }
        advance_counter(&mut counter, blocks_per_chunk);
        index += 1;
        current = next;
        n = next_n;
    }
    writer.flush().map_err(Error::from)
}

/// Decrypt an [`encrypt_raw_authenticated_stream`] stream. Each frame's tag is
/// verified in constant time before that frame is decrypted, so a wrong key or
/// a corrupted or tampered stream is reported as [`Error::AuthFailed`] instead
/// of silently producing garbage or attacker-influenced plaintext — the failure
/// mode `raw_ctr_stream` cannot detect.
#[allow(clippy::too_many_arguments)]
pub fn decrypt_raw_authenticated_stream(
    variant: Variant,
    key: &[u8],
    tweak: &[u8; 16],
    iv: &[u8],
    mac: MacId,
    chunk_size: u32,
    reader: &mut dyn Read,
    writer: &mut dyn Write,
) -> Result<()> {
    validate_raw_auth_params(variant, iv, chunk_size)?;
    if chunk_size > max_chunk_bytes() {
        return Err(Error::InvalidParams(format!(
            "chunk size {chunk_size} exceeds the accepted maximum"
        )));
    }
    let keymat = split_raw_key(variant, key)?;
    let (enc_key, mac_key) = keymat.split_at(variant.key_len());
    let cipher = Cipher::new(variant, enc_key, tweak)?;
    let blocks_per_chunk = (chunk_size as usize / variant.block_len()) as u64;

    let mut counter = iv.to_vec();
    let mut index: u64 = 0;
    loop {
        let frame = read_frame(reader, chunk_size)?;
        // Verify before decrypting (which also rejects a wrong key).
        mac::verify(
            mac,
            mac_key,
            &raw_frame_aad(tweak, iv, index, frame.is_last, &frame.ciphertext),
            &frame.tag,
        )?;

        let mut chunk = frame.ciphertext;
        cipher.ctr_apply(&counter, &mut chunk)?;
        writer.write_all(&chunk)?;

        if frame.is_last {
            break;
        }
        if chunk.len() != chunk_size as usize {
            return Err(Error::MalformedHeader(
                "non-final chunk is not full size".into(),
            ));
        }
        advance_counter(&mut counter, blocks_per_chunk);
        index += 1;
    }
    writer.flush().map_err(Error::from)
}

/// In-memory convenience wrapper over [`encrypt_raw_authenticated_stream`].
#[allow(clippy::too_many_arguments)]
pub fn encrypt_raw_authenticated_bytes(
    variant: Variant,
    key: &[u8],
    tweak: &[u8; 16],
    iv: &[u8],
    mac: MacId,
    chunk_size: u32,
    plaintext: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut reader = Cursor::new(plaintext);
    encrypt_raw_authenticated_stream(
        variant,
        key,
        tweak,
        iv,
        mac,
        chunk_size,
        &mut reader,
        &mut out,
    )?;
    Ok(out)
}

/// In-memory convenience wrapper over [`decrypt_raw_authenticated_stream`].
#[allow(clippy::too_many_arguments)]
pub fn decrypt_raw_authenticated_bytes(
    variant: Variant,
    key: &[u8],
    tweak: &[u8; 16],
    iv: &[u8],
    mac: MacId,
    chunk_size: u32,
    data: &[u8],
) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut reader = Cursor::new(data);
    decrypt_raw_authenticated_stream(
        variant,
        key,
        tweak,
        iv,
        mac,
        chunk_size,
        &mut reader,
        &mut out,
    )?;
    Ok(out)
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
) -> Result<Vec<u8>> {
    let variant = variant_from_key_len(key.len())?;
    if block.len() != variant.block_len() {
        return Err(Error::InvalidParams(format!(
            "block must be {} bytes for this key, got {}",
            variant.block_len(),
            block.len()
        )));
    }
    let mut out = block.to_vec();
    // `out` was sized to `variant.block_len()` just above, so each conversion is
    // infallible by construction.
    match variant {
        Variant::T256 => {
            let c = Threefish256::new(&fixed(key)?, tweak);
            let b: &mut [u8; 32] = (&mut out[..]).try_into().expect("out is 32 bytes");
            if decrypt {
                c.decrypt_block(b)
            } else {
                c.encrypt_block(b)
            }
        }
        Variant::T512 => {
            let c = Threefish512::new(&fixed(key)?, tweak);
            let b: &mut [u8; 64] = (&mut out[..]).try_into().expect("out is 64 bytes");
            if decrypt {
                c.decrypt_block(b)
            } else {
                c.encrypt_block(b)
            }
        }
        Variant::T1024 => {
            let c = Threefish1024::new(&fixed(key)?, tweak);
            let b: &mut [u8; 128] = (&mut out[..]).try_into().expect("out is 128 bytes");
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
    fn new(variant: Variant, key: &[u8], tweak: &[u8; 16]) -> Result<Self> {
        Ok(match variant {
            Variant::T256 => Cipher::T256(Threefish256::new(&fixed(key)?, tweak)),
            Variant::T512 => Cipher::T512(Threefish512::new(&fixed(key)?, tweak)),
            Variant::T1024 => Cipher::T1024(Threefish1024::new(&fixed(key)?, tweak)),
        })
    }

    fn ctr_apply(&self, iv: &[u8], data: &mut [u8]) -> Result<()> {
        match self {
            Cipher::T256(c) => c.ctr_apply(&fixed(iv)?, data),
            Cipher::T512(c) => c.ctr_apply(&fixed(iv)?, data),
            Cipher::T1024(c) => c.ctr_apply(&fixed(iv)?, data),
        }
        Ok(())
    }
}

/// Copy a slice of the statically expected length into a fixed-size array.
fn fixed<const N: usize>(bytes: &[u8]) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| Error::InvalidParams(format!("expected {N} bytes, got {}", bytes.len())))
}

/// Which CSPRNG `fill_random` draws from.
enum RngKind {
    Os,
    Thread,
}

/// Resolve the RNG source from the optional `DORADO_RNG` value. Both choices are
/// CSPRNGs, so this can never select an insecure source; an unrecognized value is an
/// error rather than a silent fallback. Pure, so it is unit-tested without env state.
fn rng_kind(override_opt: Option<&str>) -> Result<RngKind> {
    match override_opt {
        None | Some("") | Some("os") => Ok(RngKind::Os),
        Some("thread") => Ok(RngKind::Thread),
        Some(other) => Err(Error::InvalidParams(format!(
            "unknown DORADO_RNG={other:?} (expected \"os\" or \"thread\")"
        ))),
    }
}

/// Fill `buf` with cryptographically secure random bytes. The source defaults to the
/// OS CSPRNG (`OsRng`); set `DORADO_RNG=thread` to use `rand`'s thread-local CSPRNG.
fn fill_random(buf: &mut [u8]) -> Result<()> {
    match rng_kind(std::env::var("DORADO_RNG").ok().as_deref())? {
        RngKind::Os => rand::rngs::OsRng.fill_bytes(buf),
        RngKind::Thread => rand::thread_rng().fill_bytes(buf),
    }
    Ok(())
}

/// The effective cap on an accepted chunk size: [`DEFAULT_MAX_CHUNK_BYTES`] unless
/// `DORADO_MAX_CHUNK_BYTES` overrides it. Any override is clamped to
/// `(0, MAX_CHUNK_BYTES]`, so it can only tighten the bound, never weaken it past the
/// hard ceiling; unparseable values fall back to the default.
pub fn max_chunk_bytes() -> u32 {
    chunk_cap_from(std::env::var("DORADO_MAX_CHUNK_BYTES").ok().as_deref())
}

/// Pure resolution of the chunk-size cap from an optional override string, so the
/// clamping is unit-tested without env state.
fn chunk_cap_from(override_opt: Option<&str>) -> u32 {
    match override_opt {
        Some(s) => match s.trim().parse::<u32>() {
            Ok(v) => v.clamp(1, MAX_CHUNK_BYTES),
            Err(_) => DEFAULT_MAX_CHUNK_BYTES,
        },
        None => DEFAULT_MAX_CHUNK_BYTES,
    }
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
fn read_frame(r: &mut dyn Read, chunk_size: u32) -> Result<Frame> {
    let mut head = [0u8; 5];
    let n = read_fill(r, &mut head)?;
    if n == 0 {
        return Err(Error::MalformedHeader(
            "stream ended before the final chunk (truncated)".into(),
        ));
    }
    if n < head.len() {
        return Err(Error::MalformedHeader(
            "incomplete frame header (truncated)".into(),
        ));
    }
    let is_last = match head[0] {
        0 => false,
        1 => true,
        other => {
            return Err(Error::MalformedHeader(format!(
                "invalid frame flag {other}"
            )))
        }
    };
    let ct_len = u32::from_be_bytes([head[1], head[2], head[3], head[4]]);
    if ct_len > chunk_size {
        return Err(Error::MalformedHeader(
            "frame length exceeds the header chunk size".into(),
        ));
    }
    let mut ciphertext = vec![0u8; ct_len as usize];
    if read_fill(r, &mut ciphertext)? != ct_len as usize {
        return Err(Error::MalformedHeader("truncated frame ciphertext".into()));
    }
    let mut tag = [0u8; mac::TAG_LEN];
    if read_fill(r, &mut tag)? != mac::TAG_LEN {
        return Err(Error::MalformedHeader("truncated frame tag".into()));
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
pub fn variant_from_key_len(n: usize) -> Result<Variant> {
    match n {
        32 => Ok(Variant::T256),
        64 => Ok(Variant::T512),
        128 => Ok(Variant::T1024),
        n => Err(Error::InvalidParams(format!(
            "key must be 32, 64, or 128 bytes, got {n}"
        ))),
    }
}

/// Parse a hex string (ignoring whitespace) into bytes.
pub fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if !s.len().is_multiple_of(2) {
        return Err(Error::InvalidParams("odd number of hex digits".into()));
    }
    (0..s.len())
        .step_by(2)
        .map(|i| {
            u8::from_str_radix(&s[i..i + 2], 16)
                .map_err(|_| Error::InvalidParams(format!("invalid hex at byte {}", i / 2)))
        })
        .collect()
}

/// Parse a 16-byte tweak from hex.
pub fn parse_tweak(s: &str) -> Result<[u8; 16]> {
    let t = parse_hex(s).map_err(|e| Error::InvalidParams(format!("tweak: {e}")))?;
    t.try_into().map_err(|t: Vec<u8>| {
        Error::InvalidParams(format!("tweak must be 16 bytes, got {}", t.len()))
    })
}

#[cfg(test)]
mod tests;
