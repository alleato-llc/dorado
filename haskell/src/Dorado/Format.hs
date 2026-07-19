-- | The DRDO v4 container header: serialize and parse. The byte layout is the
-- shared wire format (see @../docs/spec.md@); all multi-byte integers are
-- big-endian. Versions 3 and 4 are read; 4 is written (v3 has no label fields).
module Dorado.Format
  ( Header (..)
  , serializeHeader
  , parseHeader
  , variantCode
  , variantFromCode
  , defaultMaxChunkBytes
  , hardMaxChunkBytes
  , chunkCapFrom
  , maxChunkBytes
  , be16
  , be32
  , be64
  ) where

import Control.Monad (unless)
import Data.Bits (shiftL, shiftR, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Char (digitToInt, isDigit, isSpace)
import Data.List (dropWhileEnd)
import Data.Word (Word16, Word32, Word64, Word8)
import System.Environment (lookupEnv)

import qualified Dorado.Kdf as Kdf
import qualified Dorado.Mac as Mac
import qualified Dorado.Threefish as TF

-- | A parsed container header. Everything here is non-secret and authenticated
-- (the whole header is bound into chunk 0's tag).
data Header = Header
  { hVersion   :: !Word8
  , hVariant   :: !TF.Variant
  , hKdf       :: !Kdf.Kdf
  , hMac       :: !Mac.Mac
  , hChunkSize :: !Word32
  , hSalt      :: !ByteString
  , hTweak     :: !ByteString   -- ^ 16 bytes
  , hIv        :: !ByteString   -- ^ block-size bytes
  , hLabel     :: !ByteString   -- ^ empty for v3 or no label
  }
  deriving (Eq, Show)

variantCode :: TF.Variant -> Word8
variantCode TF.TF256 = 0
variantCode TF.TF512 = 1
variantCode TF.TF1024 = 2

variantFromCode :: Word8 -> Either String TF.Variant
variantFromCode 0 = Right TF.TF256
variantFromCode 1 = Right TF.TF512
variantFromCode 2 = Right TF.TF1024
variantFromCode n = Left ("unknown variant code " ++ show n)

-- ---------------------------------------------------------------------------
-- Accepted chunk-size cap. The header's chunk-size field is untrusted input:
-- the decrypt paths bound it (and, through it, each frame's ct_len) against
-- this cap before allocating a buffer and before deriving any key, so a
-- crafted file cannot demand an absurd allocation.
-- ---------------------------------------------------------------------------

-- | Hard ceiling on the accepted chunk size (1 GiB), regardless of any
-- @DORADO_MAX_CHUNK_BYTES@ override.
hardMaxChunkBytes :: Word32
hardMaxChunkBytes = 1024 * 1024 * 1024

-- | Cap on the header's chunk-size field when @DORADO_MAX_CHUNK_BYTES@ is not
-- set: 64 MiB, well above the 64 KiB default chunk size.
defaultMaxChunkBytes :: Word32
defaultMaxChunkBytes = 64 * 1024 * 1024

-- | The effective cap on an accepted chunk size: 'defaultMaxChunkBytes' unless
-- @DORADO_MAX_CHUNK_BYTES@ overrides it. Any override is clamped into
-- @(0, 'hardMaxChunkBytes']@, so it can only tighten the bound, never weaken
-- it past the ceiling. Exposed so the CLI can cap encryption to match.
maxChunkBytes :: IO Word32
maxChunkBytes = chunkCapFrom <$> lookupEnv "DORADO_MAX_CHUNK_BYTES"

-- | Pure resolution of the chunk-size cap from an optional override string, so
-- the clamping is unit-tested without touching the environment. Unparseable
-- values (anything not a decimal number fitting 32 bits) fall back to the
-- default, matching the other ports.
chunkCapFrom :: Maybe String -> Word32
chunkCapFrom Nothing = defaultMaxChunkBytes
chunkCapFrom (Just s)
  | null t || not (all isDigit t) = defaultMaxChunkBytes
  | v > toInteger (maxBound :: Word32) = defaultMaxChunkBytes
  | otherwise = fromInteger (max 1 (min v (toInteger hardMaxChunkBytes)))
  where
    t = dropWhileEnd isSpace (dropWhile isSpace s)
    v = foldl' (\acc c -> acc * 10 + toInteger (digitToInt c)) 0 t

-- ---------------------------------------------------------------------------
-- Big-endian integer encoding.
-- ---------------------------------------------------------------------------

be16 :: Word16 -> ByteString
be16 w = BS.pack [fromIntegral (w `shiftR` 8), fromIntegral w]

be32 :: Word32 -> ByteString
be32 w = BS.pack [fromIntegral (w `shiftR` (8 * (3 - i))) | i <- [0 .. 3]]

be64 :: Word64 -> ByteString
be64 w = BS.pack [fromIntegral (w `shiftR` (8 * (7 - i))) | i <- [0 .. 7]]

kdfBytes :: Kdf.Kdf -> ByteString
kdfBytes (Kdf.Argon2id m t p) = BS.singleton 1 <> be32 m <> be32 t <> be32 p
kdfBytes (Kdf.Scrypt logN r p) = BS.singleton 2 <> BS.singleton logN <> be32 r <> be32 p
kdfBytes (Kdf.Pbkdf2 rounds) = BS.singleton 3 <> be32 rounds <> BS.singleton 1

-- | Serialize a header to its on-disk bytes.
serializeHeader :: Header -> ByteString
serializeHeader h =
  BS.concat
    [ C8.pack "DRDO"
    , BS.singleton (hVersion h)
    , BS.singleton (variantCode (hVariant h))
    , kdfBytes (hKdf h)
    , BS.singleton (Mac.macId (hMac h))
    , be32 (hChunkSize h)
    , BS.singleton (fromIntegral (BS.length (hSalt h)))
    , hSalt h
    , hTweak h
    , hIv h
    , label
    ]
  where
    label
      | hVersion h >= 4 = be16 (fromIntegral (BS.length (hLabel h))) <> hLabel h
      | otherwise = BS.empty

-- ---------------------------------------------------------------------------
-- Parsing (a tiny Either-monad byte reader).
-- ---------------------------------------------------------------------------

takeN :: Int -> ByteString -> Either String (ByteString, ByteString)
takeN n bs
  | BS.length bs < n = Left "unexpected end of input"
  | otherwise = Right (BS.splitAt n bs)

u8 :: ByteString -> Either String (Word8, ByteString)
u8 bs = do
  (b, r) <- takeN 1 bs
  Right (BS.head b, r)

beInt :: Int -> ByteString -> Either String (Word64, ByteString)
beInt n bs = do
  (b, r) <- takeN n bs
  Right (foldl' (\acc i -> acc `shiftL` 8 .|. fromIntegral (BS.index b i)) 0 [0 .. n - 1], r)

u16 :: ByteString -> Either String (Word16, ByteString)
u16 bs = do (v, r) <- beInt 2 bs; Right (fromIntegral v, r)

u32 :: ByteString -> Either String (Word32, ByteString)
u32 bs = do (v, r) <- beInt 4 bs; Right (fromIntegral v, r)

parseKdf :: Word8 -> ByteString -> Either String (Kdf.Kdf, ByteString)
parseKdf 1 bs = do
  (m, a) <- u32 bs
  (t, b) <- u32 a
  (p, c) <- u32 b
  Right (Kdf.Argon2id m t p, c)
parseKdf 2 bs = do
  (logN, a) <- u8 bs
  (r, b) <- u32 a
  (p, c) <- u32 b
  Right (Kdf.Scrypt logN r p, c)
parseKdf 3 bs = do
  (rounds, a) <- u32 bs
  (prf, b) <- u8 a
  unless (prf == 1) (Left ("unknown pbkdf2 prf id " ++ show prf))
  Right (Kdf.Pbkdf2 rounds, b)
parseKdf n _ = Left ("unknown kdf id " ++ show n)

-- | Parse a header, returning it and the bytes that follow (the frames).
parseHeader :: ByteString -> Either String (Header, ByteString)
parseHeader input = do
  (magic, r1) <- takeN 4 input
  unless (magic == C8.pack "DRDO") (Left "not a dorado container (bad magic)")
  (ver, r2) <- u8 r1
  unless (ver == 3 || ver == 4) (Left ("unsupported version " ++ show ver))
  (vcode, r3) <- u8 r2
  variant <- variantFromCode vcode
  (kdfId, r4) <- u8 r3
  (kdf, r5) <- parseKdf kdfId r4
  (macId, r6) <- u8 r5
  macv <- Mac.macFromId macId
  (chunkSize, r7) <- u32 r6
  (saltLen, r8) <- u8 r7
  (salt, r9) <- takeN (fromIntegral saltLen) r8
  (tweak, r10) <- takeN 16 r9
  (iv, r11) <- takeN (TF.blockSize variant) r10
  (label, r12) <-
    if ver >= 4
      then do
        (ll, ra) <- u16 r11
        takeN (fromIntegral ll) ra
      else Right (BS.empty, r11)
  Right (Header ver variant kdf macv chunkSize salt tweak iv label, r12)
