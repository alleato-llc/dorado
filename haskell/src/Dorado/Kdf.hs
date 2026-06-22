-- | Password key-derivation functions for the container, delegated to the
-- @crypton@ library, matching the other ports' use of a KDF library (the cipher
-- and hashes are from scratch; the KDFs are not). The three choices and their
-- parameters mirror the DRDO header's @kdf id@ + params encoding.
module Dorado.Kdf
  ( Kdf (..)
  , derive
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word32, Word8)

import Crypto.Error (throwCryptoError)
import Crypto.Hash.Algorithms (SHA256 (..))
import qualified Crypto.KDF.Argon2 as Argon2
import qualified Crypto.KDF.PBKDF2 as PBKDF2
import qualified Crypto.KDF.Scrypt as Scrypt

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
