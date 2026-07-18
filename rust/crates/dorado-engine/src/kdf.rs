//! Key derivation, in its two standard forms.
//!
//! [`derive_from_password`] is password-based derivation (a PBKDF): it
//! stretches a weak, guessable secret into a raw key, deliberately slowly,
//! under caller-tunable cost parameters ([`validate`] bounds untrusted ones).
//! Inside the container this reproduces the header's recipe at decryption
//! time (the parameters live in the header, see `format`; they are not
//! secret).
//!
//! [`derive_from_key`] is key-based derivation (a KBKDF): it splits an
//! already high-entropy key into independent, domain-separated children,
//! fast (one keyed hash), with no salt and no cost parameters because there
//! is nothing to stretch. The keyed hash defaults to Skein-512 (Threefish's
//! native companion); [`derive_from_key_with`] lets a caller pick the PRF
//! ([`KdfPrf`]) instead — e.g. BLAKE3 to keep a ChaCha-family construction
//! single-family top to bottom. Every secure PRF does this job identically,
//! so the choice is about matching the surrounding cipher, not security. The
//! names are the guardrail: a password must never take the fast path, and a
//! key never needs the slow one.
//!
//! The module is public because embedders of the raw-key modes need the same
//! two steps with their own parameter storage: stretch a password once per
//! session (or fetch a random key from an OS keychain), fan it out into
//! per-purpose keys, and feed those to `encrypt_raw_authenticated_*` or
//! another AEAD, rather than paying the KDF per file the way the
//! self-contained container does by design.

use crate::error::{Error, Result};

/// Pseudo-random function used by PBKDF2. Stored as a byte in the header so the
/// set can grow without breaking old files.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum PrfId {
    /// HMAC-SHA256, the only PRF currently defined.
    HmacSha256,
}

impl PrfId {
    /// The on-disk byte identifying this PRF.
    pub fn code(self) -> u8 {
        match self {
            PrfId::HmacSha256 => 1,
        }
    }

    /// Parse a PRF id byte, rejecting unknown values.
    pub fn from_code(b: u8) -> Result<Self> {
        match b {
            1 => Ok(PrfId::HmacSha256),
            n => Err(Error::MalformedHeader(format!("unknown prf id {n}"))),
        }
    }
}

/// A KDF choice together with its cost parameters. This is exactly what the
/// header stores, so `derive` can be reproduced byte for byte on decrypt.
#[derive(Clone, Copy, Debug)]
pub enum KdfParams {
    /// `m_cost` is memory in KiB; `t_cost` is iterations; `p_cost` is lanes.
    Argon2id {
        /// Memory cost in KiB.
        m_cost: u32,
        /// Time cost (number of iterations).
        t_cost: u32,
        /// Parallelism (number of lanes).
        p_cost: u32,
    },
    /// `log_n` is log2 of the CPU/memory cost; `r` and `p` are the block and
    /// parallelization factors.
    Scrypt {
        /// log2 of the CPU/memory cost parameter N.
        log_n: u8,
        /// Block-size factor.
        r: u32,
        /// Parallelization factor.
        p: u32,
    },
    /// `rounds` is the iteration count; `prf` selects the underlying PRF.
    Pbkdf2 {
        /// Iteration count.
        rounds: u32,
        /// The pseudo-random function to stretch with.
        prf: PrfId,
    },
}

/// Derive `out.len()` key bytes from `password` and `salt` using `params` —
/// password-based derivation, deliberately slow (the cost is what an
/// attacker pays per guess). For deriving from an already-strong key, use
/// [`derive_from_key`] instead.
pub fn derive_from_password(
    params: &KdfParams,
    password: &[u8],
    salt: &[u8],
    out: &mut [u8],
) -> Result<()> {
    match *params {
        KdfParams::Argon2id {
            m_cost,
            t_cost,
            p_cost,
        } => {
            use argon2::{Algorithm, Argon2, Params, Version};
            let params = Params::new(m_cost, t_cost, p_cost, Some(out.len()))
                .map_err(|e| Error::InvalidParams(format!("argon2 params: {e}")))?;
            Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
                .hash_password_into(password, salt, out)
                .map_err(|e| Error::InvalidParams(format!("argon2: {e}")))
        }
        KdfParams::Scrypt { log_n, r, p } => {
            // The `len` in scrypt's Params is only consumed by its PHC-string
            // API, which we do not use, and it rejects values above 64. The real
            // output length is `out.len()`, so pass a valid placeholder here.
            let params = scrypt::Params::new(log_n, r, p, 32)
                .map_err(|e| Error::InvalidParams(format!("scrypt params: {e}")))?;
            scrypt::scrypt(password, salt, &params, out)
                .map_err(|e| Error::InvalidParams(format!("scrypt: {e}")))
        }
        KdfParams::Pbkdf2 { rounds, prf } => match prf {
            PrfId::HmacSha256 => {
                pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, rounds, out);
                Ok(())
            }
        },
    }
}

/// The keyed hash [`derive_from_key_with`] fans a master key out with. Both
/// are secure PRFs and produce identically strong children; the choice exists
/// only to let a construction stay within one cryptographic family (Skein for
/// Threefish, BLAKE3 for a ChaCha-family cipher) rather than mixing lineages.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum KdfPrf {
    /// Skein-512 keyed hash (Threefish's native companion). The default, and
    /// what [`derive_from_key`] uses. Accepts a key of any length.
    Skein512,
    /// BLAKE3 keyed hash. Requires a 32-byte `key` (BLAKE3's keyed mode is
    /// defined only for a 256-bit key); other lengths panic.
    Blake3,
}

/// Fixed prefix domain-separating [`derive_from_key`]'s keyed hashing from
/// every other keyed use in the engine (`DRDOrawE`/`DRDOrawM` in the raw-key
/// split, `DRDOchnk`/`DRDOrwFr` in the frame MACs).
const DERIVE_FROM_KEY_DOMAIN: &[u8; 8] = b"DRDOkdrv";

/// Derive `out.len()` key bytes from an already high-entropy `key`, separated
/// by `domain` — key-based derivation (the fast form): one domain-separated
/// Skein-512 keyed hash, no salt, no cost parameters, because a strong key
/// has nothing to stretch. Deterministic: the same key and domain always
/// yield the same bytes, and different domains yield computationally
/// unrelated ones, so a caller can fan one master key out into independent
/// per-purpose keys (`derive_from_key(master, "myapp/index", ..)`,
/// `derive_from_key(master, "myapp/data", ..)`). Never pass a password here:
/// there is no stretching, so a guessable input stays guessable — that is
/// [`derive_from_password`]'s job. To fan out with a different PRF (e.g.
/// BLAKE3), use [`derive_from_key_with`].
pub fn derive_from_key(key: &[u8], domain: &str, out: &mut [u8]) {
    derive_from_key_with(KdfPrf::Skein512, key, domain, out);
}

/// [`derive_from_key`] with a caller-chosen PRF ([`KdfPrf`]). The domain
/// separation, determinism, and "never pass a password" contract are exactly
/// the same; only the underlying keyed hash changes. With [`KdfPrf::Skein512`]
/// this is byte-for-byte identical to [`derive_from_key`]. [`KdfPrf::Blake3`]
/// requires `key` to be 32 bytes.
pub fn derive_from_key_with(prf: KdfPrf, key: &[u8], domain: &str, out: &mut [u8]) {
    match prf {
        KdfPrf::Skein512 => {
            // Streaming update(A) then update(B) equals update(A‖B), so this
            // matches a one-shot MAC over the concatenated message.
            let mut h = dorado::skein::Skein512::new_mac(key, out.len());
            h.update(DERIVE_FROM_KEY_DOMAIN);
            h.update(domain.as_bytes());
            h.finalize_into(out);
        }
        KdfPrf::Blake3 => {
            let key: [u8; 32] = key
                .try_into()
                .expect("derive_from_key_with(Blake3) requires a 32-byte key");
            let mut msg = Vec::with_capacity(DERIVE_FROM_KEY_DOMAIN.len() + domain.len());
            msg.extend_from_slice(DERIVE_FROM_KEY_DOMAIN);
            msg.extend_from_slice(domain.as_bytes());
            dorado::blake3::keyed_mac_into(out, &key, &msg);
        }
    }
}

/// Reject KDF parameters whose cost is unreasonably large. Decryption reads the
/// cost from an untrusted file header, so without this a crafted file could
/// request gigabytes of memory or a multi-minute derivation (a denial of
/// service). The caps are generous, well above any sane real-world setting.
pub fn validate(params: &KdfParams) -> Result<()> {
    match *params {
        KdfParams::Argon2id {
            m_cost,
            t_cost,
            p_cost,
        } => {
            if m_cost > 1 << 21 {
                return Err(Error::InvalidParams("argon2 memory cost too large".into()));
                // > 2 GiB
            }
            if t_cost > 64 {
                return Err(Error::InvalidParams("argon2 time cost too large".into()));
            }
            if p_cost > 16 {
                return Err(Error::InvalidParams("argon2 parallelism too large".into()));
            }
        }
        KdfParams::Scrypt { log_n, r, p } => {
            if log_n > 21 {
                return Err(Error::InvalidParams(
                    "scrypt cost (log2 N) too large".into(),
                ));
            }
            if r > 32 {
                return Err(Error::InvalidParams(
                    "scrypt block factor r too large".into(),
                ));
            }
            if p > 16 {
                return Err(Error::InvalidParams(
                    "scrypt parallelism p too large".into(),
                ));
            }
        }
        KdfParams::Pbkdf2 { rounds, .. } => {
            if rounds == 0 {
                // Zero rounds would "derive" an all-zero key without error.
                return Err(Error::InvalidParams("pbkdf2 rounds must be nonzero".into()));
            }
            if rounds > 50_000_000 {
                return Err(Error::InvalidParams("pbkdf2 rounds too large".into()));
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
