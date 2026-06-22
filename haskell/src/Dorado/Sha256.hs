{-# LANGUAGE BangPatterns #-}

-- | SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 2104), from scratch. Unlike the
-- little-endian Threefish/BLAKE3, SHA-256 is big-endian. The compression keeps
-- eight working words across blocks; the message schedule expands each 64-byte
-- block to 64 words. Strict throughout (a strict 8-word state record, no thunk
-- buildup over the 64 rounds).
--
-- HMAC-SHA256 is dorado's HMAC-based MAC option. SHA-256 and HMAC are fully
-- standardized, so matching the FIPS/RFC test vectors also fixes cross-compat
-- with the other ports.
module Dorado.Sha256
  ( sha256
  , hmacSha256
  ) where

import Control.Monad (forM_)
import Data.Array.ST (newArray, readArray, runSTUArray, writeArray)
import Data.Array.Unboxed (UArray, listArray, (!))
import Data.Bits (complement, rotateR, shiftL, shiftR, xor, (.&.), (.|.))
import Data.Word (Word32, Word64)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

h0 :: [Word32]
h0 =
  [ 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
  , 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19 ]

kTable :: UArray Int Word32
kTable = listArray (0, 63)
  [ 0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5
  , 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174
  , 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da
  , 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967
  , 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85
  , 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070
  , 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3
  , 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2 ]

-- Strict eight-word working state.
data S = S !Word32 !Word32 !Word32 !Word32 !Word32 !Word32 !Word32 !Word32

bigSig0, bigSig1, smallSig0, smallSig1 :: Word32 -> Word32
bigSig0 x = rotateR x 2 `xor` rotateR x 13 `xor` rotateR x 22
bigSig1 x = rotateR x 6 `xor` rotateR x 11 `xor` rotateR x 25
smallSig0 x = rotateR x 7 `xor` rotateR x 18 `xor` (x `shiftR` 3)
smallSig1 x = rotateR x 17 `xor` rotateR x 19 `xor` (x `shiftR` 10)

ch :: Word32 -> Word32 -> Word32 -> Word32
ch x y z = (x .&. y) `xor` (complement x .&. z)

maj :: Word32 -> Word32 -> Word32 -> Word32
maj x y z = (x .&. y) `xor` (x .&. z) `xor` (y .&. z)

-- Expand a 64-byte block to the 64-word message schedule. Built iteratively in
-- ST (the schedule is self-referential, so a strict unboxed array must be filled
-- in order, not knot-tied).
schedule :: ByteString -> UArray Int Word32
schedule block = runSTUArray $ do
  w <- newArray (0, 63) 0
  forM_ [0 .. 15] $ \t -> writeArray w t (beAt block (t * 4))
  forM_ [16 .. 63] $ \t -> do
    w2 <- readArray w (t - 2)
    w7 <- readArray w (t - 7)
    w15 <- readArray w (t - 15)
    w16 <- readArray w (t - 16)
    writeArray w t (smallSig1 w2 + w7 + smallSig0 w15 + w16)
  pure w

-- Compress one 64-byte block into the running 8-word state.
processBlock :: [Word32] -> ByteString -> [Word32]
processBlock hs block = zipWith (+) hs [a, b, c, d, e, f, g, h]
  where
    w = schedule block
    S a b c d e f g h = foldl' step (toS hs) [0 .. 63]
    toS [a0, b0, c0, d0, e0, f0, g0, h0'] = S a0 b0 c0 d0 e0 f0 g0 h0'
    toS _ = error "sha256: state must have 8 words"
    step (S sa sb sc sd se sf sg sh) t =
      let t1 = sh + bigSig1 se + ch se sf sg + kTable ! t + w ! t
          t2 = bigSig0 sa + maj sa sb sc
      in S (t1 + t2) sa sb sc (sd + t1) se sf sg

-- | SHA-256 digest (32 bytes).
sha256 :: ByteString -> ByteString
sha256 msg = wordsToBE (go h0 (pad msg))
  where
    go !hs bs
      | BS.null bs = hs
      | otherwise  = go (processBlock hs (BS.take 64 bs)) (BS.drop 64 bs)

-- Pad: 0x80, zeros, then the 64-bit big-endian bit length, to a 64-byte multiple.
pad :: ByteString -> ByteString
pad msg = msg <> BS.singleton 0x80 <> BS.replicate zeros 0 <> beLen
  where
    ml = BS.length msg
    zeros = (56 - (ml + 1) `mod` 64) `mod` 64
    bitLen = fromIntegral ml * 8 :: Word64
    beLen = BS.pack [ fromIntegral (bitLen `shiftR` (8 * (7 - k))) .&. 0xff | k <- [0 .. 7] ]

-- | HMAC-SHA256 (RFC 2104), producing a 32-byte tag.
hmacSha256 :: ByteString -> ByteString -> ByteString
hmacSha256 key msg = sha256 (opad <> sha256 (ipad <> msg))
  where
    bs = 64
    k0 = let k = if BS.length key > bs then sha256 key else key
         in k <> BS.replicate (bs - BS.length k) 0
    ipad = BS.map (xor 0x36) k0
    opad = BS.map (xor 0x5c) k0

-- ---------------------------------------------------------------------------
-- Big-endian byte/word conversion.
-- ---------------------------------------------------------------------------

beAt :: ByteString -> Int -> Word32
beAt bs off = foldl' (\acc k -> (acc `shiftL` 8) .|. fromIntegral (BS.index bs (off + k))) 0 [0 .. 3]

wordsToBE :: [Word32] -> ByteString
wordsToBE = BS.pack . concatMap be32
  where be32 w = [ fromIntegral (w `shiftR` (8 * (3 - k))) .&. 0xff | k <- [0 .. 3] ]
