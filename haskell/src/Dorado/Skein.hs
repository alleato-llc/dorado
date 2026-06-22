{-# LANGUAGE BangPatterns #-}

-- | Skein-512 hash and MAC (Skein 1.3), built on Threefish-512 via UBI (Unique
-- Block Iteration), from scratch. Skein is the hash Threefish was designed to
-- power: it threads message blocks through Threefish-512, using the tweak to
-- encode each block's byte position and type, and xors the plaintext block back
-- in (Matyas-Meyer-Oseas).
--
-- This mirrors the Rust reference's @skein.rs@; verified against the digests the
-- Rust @gyotaku@ tool produces. The output length is fixed per call because
-- Skein folds it into the configuration block that seeds the chaining value.
--
-- These are pure one-shot functions: the chaining value from folding the whole
-- message through one UBI pass is identical to the incremental block-by-block
-- form, so a streaming variant (for hashing inputs larger than memory) can be
-- added later without changing results.
module Dorado.Skein
  ( hash
  , mac
  ) where

import Data.Bits (shiftL, shiftR, xor, (.&.), (.|.))
import Data.Word (Word64)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

import Dorado.Threefish (Variant (TF512), encryptBlock, newThreefish)

block :: Int
block = 64

-- UBI block-type values (the 6-bit type field of the tweak).
tKey, tCfg, tMsg, tOut :: Word64
tKey = 0
tCfg = 4
tMsg = 48
tOut = 63

-- | Eight little-endian bytes of a 'Word64'.
le64 :: Word64 -> ByteString
le64 w = BS.pack [ fromIntegral (w `shiftR` (8 * k)) .&. 0xff | k <- [0 .. 7] ]

-- | The 128-bit UBI tweak (16 little-endian bytes) for a block at byte
-- @position@ of a pass of type @ty@, with the first/final flags. Layout: bits
-- 0-95 position (only the low 64 used), bits 120-125 type, bit 126 first, bit
-- 127 final.
tweak :: Word64 -> Word64 -> Bool -> Bool -> ByteString
tweak position ty first final = le64 position <> le64 t1
  where
    t1 = (ty `shiftL` 56)
         .|. (if first then 1 `shiftL` 62 else 0)
         .|. (if final then 1 `shiftL` 63 else 0)

-- | One UBI pass: chain @msg@ into the 64-byte chaining value @g@ under block
-- type @ty@. An empty message processes a single zero block at position 0.
ubi :: ByteString -> ByteString -> Word64 -> ByteString
ubi g0 msg ty = go g0 0 0 True
  where
    total = BS.length msg
    go !g !offset !position !first =
      let take' = min (total - offset) block
          raw = BS.take take' (BS.drop offset msg)
          blk = raw <> BS.replicate (block - take') 0
          position' = position + fromIntegral take'
          offset' = offset + take'
          final = offset' >= total
          cipher = newThreefish TF512 g (tweak position' ty first final)
          enc = encryptBlock cipher blk
          g' = BS.pack (BS.zipWith xor enc blk)
      in if final then g' else go g' offset' position' False

-- | The 32-byte Skein configuration block for an output of @outBits@ bits:
-- "SHA3" schema id, version 1, then the output length.
configBlock :: Word64 -> ByteString
configBlock outBits =
  BS.pack [0x53, 0x48, 0x41, 0x33, 1, 0, 0, 0] <> le64 outBits <> BS.replicate 16 0

-- | Produce @outLen@ output bytes from the final chaining value by running the
-- output UBI over an incrementing counter. Generates exactly as many blocks as
-- needed (no lazy-infinite-list reliance).
output :: ByteString -> Int -> ByteString
output g outLen = BS.take outLen (BS.concat [ blockFor c | c <- [0 .. nBlocks - 1] ])
  where
    nBlocks = fromIntegral ((outLen + block - 1) `div` block) :: Word64
    blockFor counter = ubi g (le64 counter) tOut

-- | Skein-512 hash of @msg@ producing @outLen@ bytes.
hash :: Int -> ByteString -> ByteString
hash outLen msg = output g1 outLen
  where
    g0 = ubi (BS.replicate block 0) (configBlock (fromIntegral outLen * 8)) tCfg
    g1 = ubi g0 msg tMsg

-- | Skein-512 MAC (keyed hash) producing @outLen@ bytes; absorbs @key@ through a
-- Key UBI first. An empty key is identical to 'hash'.
mac :: ByteString -> Int -> ByteString -> ByteString
mac key outLen msg = output g1 outLen
  where
    gKey | BS.null key = BS.replicate block 0
         | otherwise   = ubi (BS.replicate block 0) key tKey
    g0 = ubi gKey (configBlock (fromIntegral outLen * 8)) tCfg
    g1 = ubi g0 msg tMsg
