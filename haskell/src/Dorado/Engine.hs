{-# LANGUAGE BangPatterns #-}

-- | The DRDO password container: encrypt-then-MAC over a continuous CTR stream,
-- framed into chunks. Mirrors the shared construction (see @../docs/spec.md@):
-- the KDF output is split into an encryption key and a MAC key; the plaintext is
-- one continuous CTR stream from the header IV; each chunk frame carries a MAC
-- tag over @"DRDOchnk" || header(chunk 0 only) || index || is_last || ct_len ||
-- ciphertext@, and decryption verifies every frame before returning.
--
-- This is the in-memory (bytes) form; the ciphertext bytes are identical to
-- whole-file CTR, so a streaming variant can be added later without changing
-- output. Cross-compatible with the other ports' containers.
module Dorado.Engine
  ( Options (..)
  , defaultOptions
  , encryptPassword
  , encryptPasswordWith
  , decryptPassword
  ) where

import Control.Monad (unless)
import Data.Bits (shiftL, xor, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.Word (Word32, Word64, Word8)

import Crypto.Random (getRandomBytes)

import Dorado.Format
import qualified Dorado.Kdf as Kdf
import qualified Dorado.Mac as Mac
import qualified Dorado.Threefish as TF

-- | Encryption options (the non-secret choices written into the header).
data Options = Options
  { optVariant   :: TF.Variant
  , optKdf       :: Kdf.Kdf
  , optMac       :: Mac.Mac
  , optChunkSize :: Word32
  , optLabel     :: ByteString
  }

-- | Threefish-256, Argon2id (64 MiB, 3 passes, 4 lanes), Skein-512, 64 KiB chunks.
defaultOptions :: Options
defaultOptions =
  Options
    { optVariant = TF.TF256
    , optKdf = Kdf.Argon2id 65536 3 1
    , optMac = Mac.Skein512
    , optChunkSize = 65536
    , optLabel = BS.empty
    }

domain :: ByteString
domain = C8.pack "DRDOchnk"

-- | Frame authenticated data: domain || header (chunk 0 only) || index ||
-- is_last || ct_len || ciphertext.
frameAad :: ByteString -> Word64 -> Bool -> ByteString -> ByteString
frameAad headerBytes idx isLast ct =
  BS.concat
    [ domain
    , if idx == 0 then headerBytes else BS.empty
    , be64 idx
    , BS.singleton (if isLast then 1 else 0)
    , be32 (fromIntegral (BS.length ct))
    , ct
    ]

chunksOf :: Int -> ByteString -> [ByteString]
chunksOf n bs
  | BS.null bs = []
  | otherwise = BS.take n bs : chunksOf n (BS.drop n bs)

-- | Constant-time byte equality for the tag comparison.
ctEq :: ByteString -> ByteString -> Bool
ctEq a b =
  BS.length a == BS.length b
    && 0 == foldl' (\acc i -> acc .|. (BS.index a i `xor` BS.index b i)) (0 :: Word8) [0 .. BS.length a - 1]

-- | Encrypt with caller-provided salt, tweak, and IV (deterministic). The salt
-- is 16 bytes, the tweak 16 bytes, and the IV is the variant's block size.
encryptPasswordWith :: Options -> ByteString -> ByteString -> ByteString -> ByteString -> ByteString -> ByteString
encryptPasswordWith opts salt tweak iv password plaintext =
  headerBytes <> BS.concat (zipWith frame [0 ..] chunks)
  where
    variant = optVariant opts
    keyLen = TF.keySize variant
    kdfOut = Kdf.derive (optKdf opts) password salt (keyLen + 32)
    encKey = BS.take keyLen kdfOut
    macKey = BS.drop keyLen kdfOut
    tf = TF.newThreefish variant encKey tweak
    ctFull = TF.ctrApply tf iv plaintext
    header =
      Header 4 variant (optKdf opts) (optMac opts) (optChunkSize opts) salt tweak iv (optLabel opts)
    headerBytes = serializeHeader header
    chunks = if BS.null ctFull then [BS.empty] else chunksOf (fromIntegral (optChunkSize opts)) ctFull
    lastIdx = length chunks - 1
    frame :: Int -> ByteString -> ByteString
    frame idx ct =
      let isLast = idx == lastIdx
          tg = Mac.tag (optMac opts) macKey (frameAad headerBytes (fromIntegral idx) isLast ct)
       in BS.singleton (if isLast then 1 else 0) <> be32 (fromIntegral (BS.length ct)) <> ct <> tg

-- | Encrypt, drawing a fresh random salt, tweak, and IV from the system CSPRNG.
encryptPassword :: ByteString -> Options -> ByteString -> IO ByteString
encryptPassword password opts plaintext = do
  salt <- getRandomBytes 16
  tweak <- getRandomBytes 16
  iv <- getRandomBytes (TF.blockSize (optVariant opts))
  pure (encryptPasswordWith opts salt tweak iv password plaintext)

-- | Verify and decrypt a container. A wrong password, tampering, truncation, or a
-- malformed header all yield 'Left'.
decryptPassword :: ByteString -> ByteString -> Either String ByteString
decryptPassword password container = do
  (header, rest) <- parseHeader container
  let headerBytes = BS.take (BS.length container - BS.length rest) container
      variant = hVariant header
      keyLen = TF.keySize variant
      kdfOut = Kdf.derive (hKdf header) password (hSalt header) (keyLen + 32)
      encKey = BS.take keyLen kdfOut
      macKey = BS.drop keyLen kdfOut
  cts <- readFrames (hMac header) macKey headerBytes (hChunkSize header) rest
  let tf = TF.newThreefish variant encKey (hTweak header)
  Right (TF.ctrApply tf (hIv header) (BS.concat cts))

-- Read and verify frames, returning each chunk's ciphertext in order.
readFrames :: Mac.Mac -> ByteString -> ByteString -> Word32 -> ByteString -> Either String [ByteString]
readFrames macv macKey headerBytes chunkSize = go 0 []
  where
    go :: Word64 -> [ByteString] -> ByteString -> Either String [ByteString]
    go !idx acc bs
      | BS.null bs = Left "truncated: no final frame before end of input"
      | otherwise = do
          (isLastB, r1) <- takeE 1 bs
          (ctLenB, r2) <- takeE 4 r1
          let ctLen = fromIntegral (decodeBE ctLenB) :: Int
          unless (ctLen <= fromIntegral chunkSize) (Left "frame ct_len exceeds chunk size")
          (ct, r3) <- takeE ctLen r2
          (tg, r4) <- takeE 32 r3
          let isLast = BS.head isLastB == 1
          unless (isLast || fromIntegral (BS.length ct) == chunkSize)
            (Left "non-final frame is not a full chunk")
          let expected = Mac.tag macv macKey (frameAad headerBytes idx isLast ct)
          unless (ctEq expected tg) (Left "authentication failed")
          let acc' = ct : acc
          if isLast then Right (reverse acc') else go (idx + 1) acc' r4

takeE :: Int -> ByteString -> Either String (ByteString, ByteString)
takeE n bs
  | BS.length bs < n = Left "truncated frame"
  | otherwise = Right (BS.splitAt n bs)

decodeBE :: ByteString -> Word32
decodeBE b = foldl' (\acc i -> acc `shiftL` 8 .|. fromIntegral (BS.index b i)) 0 [0 .. BS.length b - 1]
