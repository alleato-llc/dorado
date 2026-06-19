//! On-disk container for password-encrypted output.
//!
//! All multi-byte integers are big-endian and every field is byte-aligned (no
//! bit packing). The layout is:
//!
//! ```text
//! magic "DRDO" (4) | version (1) | variant (1) | kdf id (1) |
//! kdf params (fixed per kdf) | mac id (1) | chunk size (u32) |
//! salt len (1) | salt | tweak (16) | iv (block size) | frames...
//! ```
//!
//! The body after the header is a sequence of authenticated frames (see `mac`
//! and the CLI streaming code); each frame carries its own HMAC tag, and the
//! header is bound into the first frame's tag. Everything in the header is
//! non-secret. A tampered header, a tampered or reordered frame, a wrong
//! password, or a truncated stream is detected on decryption.

use std::io::Read;

use crate::kdf::{KdfParams, PrfId};

pub const MAGIC: &[u8; 4] = b"DRDO";
/// Current container format version. Version 3 (no label field) is still read.
pub const VERSION: u8 = 4;
/// Upper bound on the optional label, to bound allocation when reading a header.
pub const MAX_LABEL_LEN: usize = 4096;

/// Which MAC authenticates the file. Stored as a byte so the set can grow. All
/// three produce a 32-byte tag from the 32-byte MAC key.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum MacId {
    /// HMAC-SHA256.
    HmacSha256,
    /// Skein-512 in its keyed (MAC) mode. The default.
    Skein512,
    /// BLAKE3 in keyed mode.
    Blake3,
}

impl MacId {
    /// The on-disk byte identifying this MAC.
    pub fn code(self) -> u8 {
        match self {
            MacId::HmacSha256 => 1,
            MacId::Skein512 => 2,
            MacId::Blake3 => 3,
        }
    }

    /// Parse a MAC id byte, rejecting unknown values.
    pub fn from_code(b: u8) -> Result<Self, String> {
        match b {
            1 => Ok(MacId::HmacSha256),
            2 => Ok(MacId::Skein512),
            3 => Ok(MacId::Blake3),
            n => Err(format!("unknown mac id {n}")),
        }
    }
}

/// Which Threefish block size a file uses. The code byte is stored in the
/// header and also fixes the key and IV lengths.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Variant {
    /// Threefish-256 (32-byte block, key, and IV).
    T256,
    /// Threefish-512 (64-byte block, key, and IV).
    T512,
    /// Threefish-1024 (128-byte block, key, and IV).
    T1024,
}

impl Variant {
    /// The on-disk byte identifying this variant.
    pub fn code(self) -> u8 {
        match self {
            Variant::T256 => 0,
            Variant::T512 => 1,
            Variant::T1024 => 2,
        }
    }

    /// Parse a variant code byte, rejecting unknown values.
    pub fn from_code(b: u8) -> Result<Self, String> {
        match b {
            0 => Ok(Variant::T256),
            1 => Ok(Variant::T512),
            2 => Ok(Variant::T1024),
            n => Err(format!("unknown variant code {n}")),
        }
    }

    /// Key length in bytes. The block and IV are the same size.
    pub fn key_len(self) -> usize {
        match self {
            Variant::T256 => 32,
            Variant::T512 => 64,
            Variant::T1024 => 128,
        }
    }

    /// Block length in bytes (equal to the key and IV length).
    pub fn block_len(self) -> usize {
        self.key_len()
    }
}

/// The non-secret header that precedes the ciphertext in a password file.
#[derive(Debug)]
pub struct Header {
    /// On-disk format version this header was written as. New headers use
    /// [`VERSION`]; a header read from a v3 file keeps `3` so `to_bytes`
    /// reproduces the original bytes (the header is bound into chunk 0's tag).
    pub version: u8,
    pub variant: Variant,
    pub kdf: KdfParams,
    pub mac: MacId,
    /// Plaintext bytes per authenticated frame. A multiple of the block size.
    pub chunk_size: u32,
    pub salt: Vec<u8>,
    pub tweak: [u8; 16],
    pub iv: Vec<u8>,
    /// Optional non-secret label bound into the authentication (version 4+).
    /// Empty when absent or for v3 files.
    pub label: Vec<u8>,
}

impl Header {
    /// Serialize the header to its on-disk bytes (ciphertext is appended by the
    /// caller).
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(MAGIC);
        out.push(self.version);
        out.push(self.variant.code());
        match &self.kdf {
            KdfParams::Argon2id {
                m_cost,
                t_cost,
                p_cost,
            } => {
                out.push(1);
                out.extend_from_slice(&m_cost.to_be_bytes());
                out.extend_from_slice(&t_cost.to_be_bytes());
                out.extend_from_slice(&p_cost.to_be_bytes());
            }
            KdfParams::Scrypt { log_n, r, p } => {
                out.push(2);
                out.push(*log_n);
                out.extend_from_slice(&r.to_be_bytes());
                out.extend_from_slice(&p.to_be_bytes());
            }
            KdfParams::Pbkdf2 { rounds, prf } => {
                out.push(3);
                out.extend_from_slice(&rounds.to_be_bytes());
                out.push(prf.code());
            }
        }
        out.push(self.mac.code());
        out.extend_from_slice(&self.chunk_size.to_be_bytes());
        // Salt length fits in a byte by construction (we generate 16).
        out.push(self.salt.len() as u8);
        out.extend_from_slice(&self.salt);
        out.extend_from_slice(&self.tweak);
        out.extend_from_slice(&self.iv);
        // Version 4+ appends the optional label at the end, so the v3 prefix is
        // byte-identical and v3 headers reserialize exactly.
        if self.version >= 4 {
            out.extend_from_slice(&(self.label.len() as u16).to_be_bytes());
            out.extend_from_slice(&self.label);
        }
        out
    }

    /// Read and parse a header from a stream, leaving the reader positioned at
    /// the first frame.
    pub fn read<R: Read + ?Sized>(r: &mut R) -> Result<Header, String> {
        if take(r, 4, "magic")? != MAGIC {
            return Err("not a dorado password file (bad magic)".into());
        }
        let version = u8r(r, "version")?;
        if version != 3 && version != VERSION {
            return Err(format!("unsupported format version {version}"));
        }
        let variant = Variant::from_code(u8r(r, "variant")?)?;
        let kdf = match u8r(r, "kdf id")? {
            1 => KdfParams::Argon2id {
                m_cost: u32r(r, "m_cost")?,
                t_cost: u32r(r, "t_cost")?,
                p_cost: u32r(r, "p_cost")?,
            },
            2 => KdfParams::Scrypt {
                log_n: u8r(r, "log_n")?,
                r: u32r(r, "r")?,
                p: u32r(r, "p")?,
            },
            3 => KdfParams::Pbkdf2 {
                rounds: u32r(r, "rounds")?,
                prf: PrfId::from_code(u8r(r, "prf")?)?,
            },
            n => return Err(format!("unknown kdf id {n}")),
        };
        let mac = MacId::from_code(u8r(r, "mac id")?)?;
        let chunk_size = u32r(r, "chunk size")?;
        let salt_len = u8r(r, "salt len")? as usize;
        let salt = take(r, salt_len, "salt")?;
        let mut tweak = [0u8; 16];
        tweak.copy_from_slice(&take(r, 16, "tweak")?);
        let iv = take(r, variant.block_len(), "iv")?;
        // The label is present only in version 4+.
        let label = if version >= 4 {
            let label_len = u16r(r, "label len")? as usize;
            if label_len > MAX_LABEL_LEN {
                return Err(format!("label too long ({label_len} bytes)"));
            }
            take(r, label_len, "label")?
        } else {
            Vec::new()
        };
        Ok(Header {
            version,
            variant,
            kdf,
            mac,
            chunk_size,
            salt,
            tweak,
            iv,
            label,
        })
    }

    /// Parse a header from the start of `data`, returning it and the offset at
    /// which the frames begin. Convenience wrapper over `read` for in-memory use.
    #[cfg(test)]
    pub fn parse(data: &[u8]) -> Result<(Header, usize), String> {
        let mut cur = std::io::Cursor::new(data);
        let header = Header::read(&mut cur)?;
        Ok((header, cur.position() as usize))
    }
}

/// Read exactly `n` bytes, mapping a short read to a descriptive error.
fn take<R: Read + ?Sized>(r: &mut R, n: usize, what: &str) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf)
        .map_err(|_| format!("header truncated reading {what}"))?;
    Ok(buf)
}

fn u8r<R: Read + ?Sized>(r: &mut R, what: &str) -> Result<u8, String> {
    Ok(take(r, 1, what)?[0])
}

fn u16r<R: Read + ?Sized>(r: &mut R, what: &str) -> Result<u16, String> {
    let b = take(r, 2, what)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn u32r<R: Read + ?Sized>(r: &mut R, what: &str) -> Result<u32, String> {
    let b = take(r, 4, what)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

#[cfg(test)]
mod tests;
