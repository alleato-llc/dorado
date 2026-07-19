-- | Key derivation, in its two standard forms.
--
-- 'derive' is password-based derivation (a PBKDF), delegated to the @crypton@
-- library, matching the other ports' use of a KDF library (the cipher and
-- hashes are from scratch; the password KDFs are not): it stretches a weak,
-- guessable secret into a raw key, deliberately slowly, under caller-tunable
-- cost parameters ('validate' bounds untrusted ones). The three choices and
-- their parameters mirror the DRDO header's @kdf id@ + params encoding.
--
-- 'deriveFromKey' is key-based derivation (a KBKDF): it splits an already
-- high-entropy key into independent, domain-separated children, fast (one
-- keyed hash), with no salt and no cost parameters because there is nothing
-- to stretch. The keyed hash defaults to Skein-512 (Threefish's native
-- companion, this port's own from-scratch implementation); 'deriveFromKeyWith'
-- lets a caller pick the PRF ('KdfPrf') instead, e.g. BLAKE3 to keep a
-- ChaCha-family construction single-family top to bottom. Every secure PRF
-- does this job identically, so the choice is about matching the surrounding
-- cipher, not security. The names are the guardrail: a password must never
-- take the fast path, and a key never needs the slow one.
module Dorado.Kdf
  ( Kdf (..)
  , derive
  , validate
  , KdfPrf (..)
  , deriveFromKey
  , deriveFromKeyWith
  ) where

import Data.Bits (shiftR, (.&.), (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Char (ord)
import Data.Word (Word32, Word8)

import Crypto.Error (throwCryptoError)
import Crypto.Hash.Algorithms (SHA256 (..))
import qualified Crypto.KDF.Argon2 as Argon2
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import qualified Crypto.KDF.Scrypt as Scrypt

import qualified Dorado.Blake3 as Blake3
import qualified Dorado.Skein as Skein

-- | A KDF choice with its cost parameters, as carried in the container header.
data Kdf
  = -- | Argon2id: m_cost (KiB memory), t_cost (iterations), p_cost (lanes).
    Argon2id Word32 Word32 Word32
  | -- | scrypt: log2(N), r, p.
    Scrypt Word8 Word32 Word32
  | -- | PBKDF2 with HMAC-SHA256: iteration count.
    Pbkdf2 Word32
  deriving (Eq, Show)

-- | Derive @outLen@ key bytes from @password@ and @salt@. The container asks for
-- key_len + 32 bytes and splits the result into the encryption key and MAC key.
-- Password-based derivation, deliberately slow (the cost is what an attacker
-- pays per guess); for deriving from an already-strong key, use 'deriveFromKey'
-- instead.
derive :: Kdf -> ByteString -> ByteString -> Int -> ByteString
derive kdf password salt outLen = case kdf of
  Argon2id mCost tCost pCost ->
    throwCryptoError $
      Argon2.hash
        Argon2.Options
          { Argon2.iterations = tCost
          , Argon2.memory = mCost
          , Argon2.parallelism = pCost
          , Argon2.variant = Argon2.Argon2id
          , Argon2.version = Argon2.Version13
          }
        password
        salt
        outLen
  Scrypt logN r p ->
    Scrypt.generate
      Scrypt.Parameters
        { Scrypt.n = 2 ^ logN
        , Scrypt.r = fromIntegral r
        , Scrypt.p = fromIntegral p
        , Scrypt.outputLength = outLen
        }
      password
      salt
  Pbkdf2 rounds ->
    PBKDF2.generate
      (PBKDF2.prfHMAC SHA256)
      PBKDF2.Parameters
        { PBKDF2.iterCounts = fromIntegral rounds
        , PBKDF2.outputLength = outLen
        }
      password
      salt

-- | Reject KDF parameters whose cost is unreasonably large. Decryption reads
-- the cost from an untrusted file header, so without this a crafted file could
-- request gigabytes of memory or a multi-minute derivation (a denial of
-- service). The caps are generous, well above any sane real-world setting, and
-- match the other ports.
validate :: Kdf -> Either String ()
validate (Argon2id mCost tCost pCost)
  | mCost > 2 ^ (21 :: Int) = Left "argon2 memory cost too large" -- > 2 GiB
  | tCost > 64 = Left "argon2 time cost too large"
  | pCost > 16 = Left "argon2 parallelism too large"
  | otherwise = Right ()
validate (Scrypt logN r p)
  | logN > 21 = Left "scrypt cost (log2 N) too large"
  | r > 32 = Left "scrypt block factor r too large"
  | p > 16 = Left "scrypt parallelism p too large"
  | otherwise = Right ()
validate (Pbkdf2 rounds)
  -- Zero rounds would "derive" an all-zero key without error.
  | rounds == 0 = Left "pbkdf2 rounds must be nonzero"
  | rounds > 50000000 = Left "pbkdf2 rounds too large"
  | otherwise = Right ()

-- | The keyed hash 'deriveFromKeyWith' fans a master key out with. Both are
-- secure PRFs and produce identically strong children; the choice exists only
-- to let a construction stay within one cryptographic family (Skein for
-- Threefish, BLAKE3 for a ChaCha-family cipher) rather than mixing lineages.
data KdfPrf
  = -- | Skein-512 keyed hash (Threefish's native companion). The default, and
    -- what 'deriveFromKey' uses. Accepts a key of any length.
    Skein512
  | -- | BLAKE3 keyed hash. Requires a 32-byte key (BLAKE3's keyed mode is
    -- defined only for a 256-bit key); other lengths are a 'Left'.
    Blake3
  deriving (Eq, Show)

-- | Fixed prefix domain-separating 'deriveFromKey''s keyed hashing from every
-- other keyed use in the engine (@DRDOrawE@\/@DRDOrawM@ in the raw-key split,
-- @DRDOchnk@\/@DRDOrwFr@ in the frame MACs).
deriveFromKeyDomain :: ByteString
deriveFromKeyDomain = C8.pack "DRDOkdrv"

-- | Derive @outLen@ key bytes from an already high-entropy @key@, separated by
-- @domain@ (its UTF-8 bytes are hashed): key-based derivation (the fast
-- form): one domain-separated Skein-512 keyed hash, no salt, no cost
-- parameters, because a strong key has nothing to stretch. Deterministic: the
-- same key and domain always yield the same bytes, and different domains yield
-- computationally unrelated ones, so a caller can fan one master key out into
-- independent per-purpose keys (@deriveFromKey master \"myapp\/index\" 32@,
-- @deriveFromKey master \"myapp\/data\" 32@). Never pass a password here:
-- there is no stretching, so a guessable input stays guessable; that is
-- 'derive''s job. To fan out with a different PRF (e.g. BLAKE3), use
-- 'deriveFromKeyWith'.
deriveFromKey :: ByteString -> String -> Int -> ByteString
deriveFromKey key domain outLen =
  Skein.mac key outLen (deriveFromKeyDomain <> utf8 domain)

-- | 'deriveFromKey' with a caller-chosen PRF ('KdfPrf'). The domain
-- separation, determinism, and "never pass a password" contract are exactly
-- the same; only the underlying keyed hash changes. With 'Skein512' this is
-- byte-for-byte identical to 'deriveFromKey'. 'Blake3' requires @key@ to be
-- 32 bytes; any other length is a 'Left'.
deriveFromKeyWith :: KdfPrf -> ByteString -> String -> Int -> Either String ByteString
deriveFromKeyWith Skein512 key domain outLen = Right (deriveFromKey key domain outLen)
deriveFromKeyWith Blake3 key domain outLen
  | BS.length key /= 32 =
      Left
        ( "deriveFromKeyWith Blake3 requires a 32-byte key, got "
            ++ show (BS.length key)
        )
  | otherwise = Right (Blake3.keyedMac key outLen (deriveFromKeyDomain <> utf8 domain))

-- UTF-8 encode a domain string (no @text@ dependency; domains are short).
utf8 :: String -> ByteString
utf8 = BS.pack . concatMap enc
  where
    enc :: Char -> [Word8]
    enc ch
      | o < 0x80 = [fromIntegral o]
      | o < 0x800 = [0xc0 .|. hi 6, cont 0]
      | o < 0x10000 = [0xe0 .|. hi 12, cont 6, cont 0]
      | otherwise = [0xf0 .|. hi 18, cont 12, cont 6, cont 0]
      where
        o = ord ch
        hi sh = fromIntegral (o `shiftR` sh)
        cont sh = 0x80 .|. (fromIntegral (o `shiftR` sh) .&. 0x3f)
