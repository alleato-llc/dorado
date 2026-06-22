{-# LANGUAGE BangPatterns #-}

-- | BLAKE3 hash and keyed MAC, from scratch. BLAKE3 is a Merkle-tree hash: the
-- input is split into 1024-byte chunks, each chunk compressed block by block into
-- a chaining value, and chunk chaining values combined pairwise into parent nodes
-- up to a single root. Domain-separation flags keep chunks, parents, the root,
-- and keyed mode distinct. The compression is a BLAKE2s-style ARX function.
--
-- Mirrors the Rust reference's @blake3.rs@; verified against its digests. The
-- compression runs in 'Control.Monad.ST' over an unboxed mutable array (strict,
-- in-place); the chunk-stack tree is built with pure 'Word32' arithmetic, which
-- wraps modulo 2^32 as required. This is a one-shot hasher (the whole input is in
-- memory); a streaming variant can be added later without changing results.
--
-- Output is an extendable-output function: @outLen@ may exceed 32 bytes.
module Dorado.Blake3
  ( hash
  , keyedMac
  ) where

import Control.Monad (forM_)
import Control.Monad.ST (ST, runST)
import Data.Array.ST (STUArray, getElems, newListArray, readArray, writeArray)
import Data.Array.Unboxed (UArray, listArray, (!))
import Data.Bits (rotateR, shiftL, shiftR, xor, (.&.), (.|.))
import Data.Word (Word32, Word64)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

blockLen, chunkLen :: Int
blockLen = 64
chunkLen = 1024

chunkStart, chunkEnd, parentFlag, rootFlag, keyedHash :: Word32
chunkStart = 1
chunkEnd = 2
parentFlag = 4
rootFlag = 8
keyedHash = 16

ivConst :: [Word32]
ivConst =
  [ 0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A
  , 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19 ]

msgPermutation :: [Int]
msgPermutation = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8]

new16 :: [Word32] -> ST s (STUArray s Int Word32)
new16 = newListArray (0, 15)

-- The BLAKE3 G mixing function on four state words.
gmix :: STUArray s Int Word32 -> Int -> Int -> Int -> Int -> Word32 -> Word32 -> ST s ()
gmix st a b c d mx my = do
  va <- readArray st a
  vb <- readArray st b
  vc <- readArray st c
  vd <- readArray st d
  let a1 = va + vb + mx
      d1 = (vd `xor` a1) `rotateR` 16
      c1 = vc + d1
      b1 = (vb `xor` c1) `rotateR` 12
      a2 = a1 + b1 + my
      d2 = (d1 `xor` a2) `rotateR` 8
      c2 = c1 + d2
      b2 = (b1 `xor` c2) `rotateR` 7
  writeArray st a a2
  writeArray st b b2
  writeArray st c c2
  writeArray st d d2

-- | The compression function: 16 output words for a chaining value, message
-- block, counter, block length, and flags.
compress :: [Word32] -> [Word32] -> Word64 -> Word32 -> Word32 -> [Word32]
compress cv block counter bl flags = runST $ do
  st <- new16 initial
  let doRound m = do
        gmix st 0 4 8 12 (m ! 0) (m ! 1)
        gmix st 1 5 9 13 (m ! 2) (m ! 3)
        gmix st 2 6 10 14 (m ! 4) (m ! 5)
        gmix st 3 7 11 15 (m ! 6) (m ! 7)
        gmix st 0 5 10 15 (m ! 8) (m ! 9)
        gmix st 1 6 11 12 (m ! 10) (m ! 11)
        gmix st 2 7 8 13 (m ! 12) (m ! 13)
        gmix st 3 4 9 14 (m ! 14) (m ! 15)
      loop !r m = do
        doRound m
        if r < 6 then loop (r + 1) (permute m) else pure ()
  loop (0 :: Int) (listArray (0, 15) block :: UArray Int Word32)
  forM_ [0 .. 7] $ \i -> do
    si <- readArray st i
    si8 <- readArray st (i + 8)
    writeArray st i (si `xor` si8)
    writeArray st (i + 8) (si8 `xor` (cv !! i))
  getElems st
  where
    initial = take 8 cv ++ take 4 ivConst ++
              [fromIntegral counter, fromIntegral (counter `shiftR` 32), bl, flags]
    permute m = listArray (0, 15) [ m ! (msgPermutation !! i) | i <- [0 .. 15] ] :: UArray Int Word32

-- A tree node, enough to make a chaining value or root output.
data Output = Output
  { oCv      :: ![Word32]
  , oBlock   :: ![Word32]
  , oCounter :: !Word64
  , oBlockLen :: !Word32
  , oFlags   :: !Word32
  }

chainingValue :: Output -> [Word32]
chainingValue o = take 8 (compress (oCv o) (oBlock o) (oCounter o) (oBlockLen o) (oFlags o))

parentOutput :: [Word32] -> [Word32] -> [Word32] -> Word32 -> Output
parentOutput left right key baseFlags =
  Output key (left ++ right) 0 (fromIntegral blockLen) (baseFlags .|. parentFlag)

parentCv :: [Word32] -> [Word32] -> [Word32] -> Word32 -> [Word32]
parentCv left right key flags = chainingValue (parentOutput left right key flags)

-- | The Output of one chunk (up to 1024 bytes): compress full blocks into the
-- chaining value, holding back the final block for CHUNK_END.
chunkOutput :: [Word32] -> Word64 -> Word32 -> ByteString -> Output
chunkOutput key counter baseFlags = go key 0
  where
    go cv compressed bytes
      | BS.length bytes > blockLen =
          let blk = BS.take blockLen bytes
              flags = baseFlags .|. (if compressed == (0 :: Int) then chunkStart else 0)
              out = compress cv (wordsFromBlock blk) counter (fromIntegral blockLen) flags
          in go (take 8 out) (compressed + 1) (BS.drop blockLen bytes)
      | otherwise =
          Output
            { oCv = cv
            , oBlock = wordsFromBlock bytes
            , oCounter = counter
            , oBlockLen = fromIntegral (BS.length bytes)
            , oFlags = baseFlags .|. (if compressed == 0 then chunkStart else 0) .|. chunkEnd
            }

-- Merge a finished chunk's chaining value into the subtree stack (head = top):
-- combine with the top while the running chunk count is even, then push.
addChunkCv :: [Word32] -> Word32 -> [[Word32]] -> [Word32] -> Word64 -> [[Word32]]
addChunkCv key flags stack0 newCv0 total0 = loop newCv0 total0 stack0
  where
    loop cv tc st
      | tc .&. 1 == 0 = case st of
          (left : rest) -> loop (parentCv left cv key flags) (tc `shiftR` 1) rest
          []            -> cv : st  -- unreachable: count parity guarantees a left sibling
      | otherwise = cv : st

-- Split into 1024-byte chunks; empty input is a single empty chunk.
splitChunks :: ByteString -> [ByteString]
splitChunks bs
  | BS.null bs = [BS.empty]
  | otherwise  = go bs
  where
    go b | BS.null b = []
         | otherwise = BS.take chunkLen b : go (BS.drop chunkLen b)

-- Build the root Output for an input under a key and base flags.
rootNode :: [Word32] -> Word32 -> ByteString -> Output
rootNode key flags input = foldl' fold lastOut stack
  where
    chunks = splitChunks input
    n = length chunks
    completed = zip [0 ..] (init chunks)        -- all but the last chunk
    stack = fst (foldl' step ([], 0 :: Word64) completed)
    step (st, _) (i, cbytes) =
      let cv = chainingValue (chunkOutput key i flags cbytes)
      in (addChunkCv key flags st cv (i + 1), i + 1)
    lastOut = chunkOutput key (fromIntegral (n - 1)) flags (last chunks)
    fold out left = parentOutput left (chainingValue out) key flags

-- Squeeze root output bytes (XOF), 64 bytes per counter block.
rootBytes :: Output -> Int -> ByteString
rootBytes o outLen = BS.take outLen (BS.concat [ blockOut c | c <- [0 .. nBlocks - 1] ])
  where
    nBlocks = fromIntegral ((outLen + blockLen - 1) `div` blockLen) :: Word64
    blockOut c = wordsToBytes (compress (oCv o) (oBlock o) c (oBlockLen o) (oFlags o .|. rootFlag))

-- | BLAKE3 hash of @input@ producing @outLen@ bytes (XOF for @outLen@ > 32).
hash :: Int -> ByteString -> ByteString
hash outLen input = rootBytes (rootNode ivConst 0 input) outLen

-- | BLAKE3 keyed MAC under a 32-byte @key@, producing @outLen@ bytes.
keyedMac :: ByteString -> Int -> ByteString -> ByteString
keyedMac key outLen input = rootBytes (rootNode (wordsFromKey key) keyedHash input) outLen

-- ---------------------------------------------------------------------------
-- Little-endian byte/word conversion.
-- ---------------------------------------------------------------------------

le32At :: ByteString -> Int -> Word32
le32At bs off =
  foldl' (\acc k -> acc .|. (fromIntegral (BS.index bs (off + k)) `shiftL` (8 * k))) 0 [0 .. 3]

-- Bytes (<= 64) into 16 little-endian words, zero-padded to a full block.
wordsFromBlock :: ByteString -> [Word32]
wordsFromBlock bs = [ le32At padded (i * 4) | i <- [0 .. 15] ]
  where padded = bs <> BS.replicate (blockLen - BS.length bs) 0

-- A 32-byte key into 8 little-endian words.
wordsFromKey :: ByteString -> [Word32]
wordsFromKey key = [ le32At key (i * 4) | i <- [0 .. 7] ]

-- 16 words into 64 little-endian bytes.
wordsToBytes :: [Word32] -> ByteString
wordsToBytes = BS.pack . concatMap toLE
  where toLE w = [ fromIntegral (w `shiftR` (8 * k)) .&. 0xff | k <- [0 .. 3] ]
