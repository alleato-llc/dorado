//! Password-based key derivation for the CLI.
//!
//! Wraps Argon2id, scrypt, and PBKDF2-HMAC-SHA256 behind a single `derive`
//! call that stretches a password into a raw Threefish key of the requested
//! length. The parameters live in the file header (see `format`), so they are
//! not secret; they only need to be reproduced at decryption time.

/// Pseudo-random function used by PBKDF2. Stored as a byte in the header so the
/// set can grow without breaking old files.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PrfId {
    HmacSha256,
}

impl PrfId {
    pub fn code(self) -> u8 {
        match self {
            PrfId::HmacSha256 => 1,
        }
    }

    pub fn from_code(b: u8) -> Result<Self, String> {
        match b {
            1 => Ok(PrfId::HmacSha256),
            n => Err(format!("unknown prf id {n}")),
        }
    }
}

/// A KDF choice together with its cost parameters. This is exactly what the
/// header stores, so `derive` can be reproduced byte for byte on decrypt.
#[derive(Clone, Copy, Debug)]
pub enum KdfParams {
    /// `m_cost` is memory in KiB; `t_cost` is iterations; `p_cost` is lanes.
    Argon2id {
        m_cost: u32,
        t_cost: u32,
        p_cost: u32,
    },
    /// `log_n` is log2 of the CPU/memory cost; `r` and `p` are the block and
    /// parallelization factors.
    Scrypt { log_n: u8, r: u32, p: u32 },
    /// `rounds` is the iteration count; `prf` selects the underlying PRF.
    Pbkdf2 { rounds: u32, prf: PrfId },
}

/// Derive `out.len()` key bytes from `password` and `salt` using `params`.
pub fn derive(
    params: &KdfParams,
    password: &[u8],
    salt: &[u8],
    out: &mut [u8],
) -> Result<(), String> {
    match *params {
        KdfParams::Argon2id {
            m_cost,
            t_cost,
            p_cost,
        } => {
            use argon2::{Algorithm, Argon2, Params, Version};
            let params = Params::new(m_cost, t_cost, p_cost, Some(out.len()))
                .map_err(|e| format!("argon2 params: {e}"))?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(password, salt, out)
                .map_err(|e| format!("argon2: {e}"))
        }
        KdfParams::Scrypt { log_n, r, p } => {
            // The `len` in scrypt's Params is only consumed by its PHC-string
            // API, which we do not use, and it rejects values above 64. The real
            // output length is `out.len()`, so pass a valid placeholder here.
            let params =
                scrypt::Params::new(log_n, r, p, 32).map_err(|e| format!("scrypt params: {e}"))?;
            scrypt::scrypt(password, salt, &params, out).map_err(|e| format!("scrypt: {e}"))
        }
        KdfParams::Pbkdf2 { rounds, prf } => match prf {
            PrfId::HmacSha256 => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, rounds, out);
                Ok(())
            }
        },
    }
}

#[cfg(test)]
mod tests;
