{-# LANGUAGE BangPatterns #-}

-- | Threefish tweakable block cipher (256/512/1024-bit) following the Skein 1.3
-- specification, plus CTR mode. A from-scratch, pure-ARX implementation (add /
-- rotate / xor) with no lookup tables, verified against the official Crypto++
-- known-answer vectors.
--
-- Performance note: Haskell is lazy by default, which would be ruinous for a
-- tight ARX loop (thunk buildup). This module is strict throughout. The block
-- transform runs in 'Control.Monad.ST' over an unboxed mutable array
-- ('STUArray'), so the mutation is in-place and allocation-free, but the public
-- functions stay pure (via 'runST') and total. The 64-bit ARX is native 'Word64'
-- arithmetic, which wraps modulo 2^64 exactly as the cipher requires.
--
-- This is the Go/Rust-equivalent core of the dorado Haskell port.
module Dorado.Threefish
  ( Variant (..)
  , Threefish
  , blockSize
  , keySize
  , newThreefish
  , encryptBlock
  , decryptBlock
  , ctrApply
  ) where

import Control.Monad (forM_, when)
import Control.Monad.ST (ST, runST)
import Data.Array.ST (STUArray, newArray, newListArray, readArray, writeArray, getElems)
import Data.Array.Unboxed (UArray, listArray, (!))
import Data.Bits (rotateL, rotateR, shiftL, shiftR, xor, (.|.), (.&.))
import Data.Word (Word64, Word8)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

-- | Key-schedule constant (Skein 1.3). Keeps the extended key word from being
-- all-zero and frustrates rotational cryptanalysis.
c240 :: Word64
c240 = 0x1BD11BDAA9FC1A22

-- | The three block sizes.
data Variant = TF256 | TF512 | TF1024
  deriving (Eq, Show)

-- | A key-scheduled Threefish instance: the extended key (Nw+1 words), the
-- extended tweak (3 words), and the per-variant tables. Strict fields.
data Threefish = Threefish
  { tfNw     :: !Int
  , tfRounds :: !Int
  , tfRot    :: !(UArray Int Int)   -- ^ flattened rot[lane*8 + (round `mod` 8)]
  , tfPerm   :: !(UArray Int Int)
  , tfEk     :: !(UArray Int Word64) -- ^ length Nw+1
  , tfEt     :: !(UArray Int Word64) -- ^ length 3
  }

-- | Block (and key) size in bytes for a variant.
blockSize :: Variant -> Int
blockSize v = variantNw v * 8

-- | Key size in bytes (equals the block size).
keySize :: Variant -> Int
keySize = blockSize

variantNw :: Variant -> Int
variantNw TF256 = 4
variantNw TF512 = 8
variantNw TF1024 = 16

variantRounds :: Variant -> Int
variantRounds TF256 = 72
variantRounds TF512 = 72
variantRounds TF1024 = 80

-- rot[lane][round `mod` 8], laid out lane-major. Skein 1.3, Table 4.
variantRot :: Variant -> [Int]
variantRot TF256 =
  [ 14, 52, 23,  5, 25, 46, 58, 32
  , 16, 57, 40, 37, 33, 12, 22, 32 ]
variantRot TF512 =
  [ 46, 33, 17, 44, 39, 13, 25,  8
  , 36, 27, 49,  9, 30, 50, 29, 35
  , 19, 14, 36, 54, 34, 10, 39, 56
  , 37, 42, 39, 56, 24, 17, 43, 22 ]
variantRot TF1024 =
  [ 24, 38, 33,  5, 41, 16, 31,  9
  , 13, 19,  4, 20,  9, 34, 44, 48
  ,  8, 10, 51, 48, 37, 56, 47, 35
  , 47, 55, 13, 41, 31, 51, 46, 52
  ,  8, 49, 34, 47, 12,  4, 19, 23
  , 17, 18, 41, 28, 47, 53, 42, 31
  , 22, 23, 59, 16, 44, 42, 44, 37
  , 37, 52, 17, 25, 30, 41, 25, 20 ]

variantPerm :: Variant -> [Int]
variantPerm TF256 = [0, 3, 2, 1]
variantPerm TF512 = [2, 1, 4, 7, 6, 5, 0, 3]
variantPerm TF1024 = [0, 9, 2, 13, 6, 11, 4, 15, 10, 7, 12, 3, 14, 5, 8, 1]

-- | Build an instance from a key and a 16-byte tweak (both little-endian). The
-- key length must equal 'keySize' for the variant.
newThreefish :: Variant -> ByteString -> ByteString -> Threefish
newThreefish v key tweak =
  Threefish
    { tfNw = nw
    , tfRounds = variantRounds v
    , tfRot = listArray (0, nw * 4 - 1) (variantRot v)
    , tfPerm = listArray (0, nw - 1) (variantPerm v)
    , tfEk = listArray (0, nw) (kw ++ [parity])
    , tfEt = listArray (0, 2) [t0, t1, t0 `xor` t1]
    }
  where
    nw = variantNw v
    kw = bytesToWords key
    parity = foldl' xor c240 kw
    tw = bytesToWords tweak
    (t0, t1) = case tw of
      (a : b : _) -> (a, b)
      _           -> (0, 0)

-- ---------------------------------------------------------------------------
-- The ST engine: in-place block transform over an unboxed mutable array.
-- ---------------------------------------------------------------------------

newWords :: [Word64] -> ST s (STUArray s Int Word64)
newWords xs = newListArray (0, length xs - 1) xs

newScratch :: Int -> ST s (STUArray s Int Word64)
newScratch n = newArray (0, n - 1) 0

-- | Inject subkey @s@ into the state (word-wise, mod 2^64).
addSubkey :: Threefish -> STUArray s Int Word64 -> Int -> ST s ()
addSubkey tf st s =
  forM_ [0 .. nw - 1] $ \i -> do
    old <- readArray st i
    writeArray st i (old + subkeyWord tf s i)
  where nw = tfNw tf

-- | Inverse of 'addSubkey'.
subSubkey :: Threefish -> STUArray s Int Word64 -> Int -> ST s ()
subSubkey tf st s =
  forM_ [0 .. nw - 1] $ \i -> do
    old <- readArray st i
    writeArray st i (old - subkeyWord tf s i)
  where nw = tfNw tf

-- | The @i@-th word of subkey @s@ (key word, with the two tweak words and the
-- round counter folded into the top three positions).
subkeyWord :: Threefish -> Int -> Int -> Word64
subkeyWord tf s i
  | i == nw - 3 = k0 + tfEt tf ! (s `mod` 3)
  | i == nw - 2 = k0 + tfEt tf ! ((s + 1) `mod` 3)
  | i == nw - 1 = k0 + fromIntegral s
  | otherwise   = k0
  where
    nw = tfNw tf
    k0 = tfEk tf ! ((s + i) `mod` (nw + 1))

-- | Encrypt one block of Nw words in place.
encryptWords :: Threefish -> [Word64] -> [Word64]
encryptWords tf input = runST $ do
  st <- newWords input
  scratch <- newScratch nw
  forM_ [0 .. rounds - 1] $ \r -> do
    when (r `mod` 4 == 0) $ addSubkey tf st (r `div` 4)
    forM_ [0 .. nw `div` 2 - 1] $ \j -> do
      x0 <- readArray st (2 * j)
      x1 <- readArray st (2 * j + 1)
      let y0 = x0 + x1
          y1 = (x1 `rotateL` (tfRot tf ! (j * 8 + (r `mod` 8)))) `xor` y0
      writeArray st (2 * j) y0
      writeArray st (2 * j + 1) y1
    permute st scratch
  addSubkey tf st (rounds `div` 4)
  getElems st
  where
    nw = tfNw tf
    rounds = tfRounds tf
    permute st scratch = do
      forM_ [0 .. nw - 1] $ \i -> readArray st (tfPerm tf ! i) >>= writeArray scratch i
      forM_ [0 .. nw - 1] $ \i -> readArray scratch i >>= writeArray st i

-- | Decrypt one block of Nw words in place (exact inverse of 'encryptWords').
decryptWords :: Threefish -> [Word64] -> [Word64]
decryptWords tf input = runST $ do
  st <- newWords input
  scratch <- newScratch nw
  subSubkey tf st (rounds `div` 4)
  forM_ (reverse [0 .. rounds - 1]) $ \r -> do
    unpermute st scratch
    forM_ [0 .. nw `div` 2 - 1] $ \j -> do
      y0 <- readArray st (2 * j)
      y1 <- readArray st (2 * j + 1)
      let x1 = (y1 `xor` y0) `rotateR` (tfRot tf ! (j * 8 + (r `mod` 8)))
          x0 = y0 - x1
      writeArray st (2 * j) x0
      writeArray st (2 * j + 1) x1
    when (r `mod` 4 == 0) $ subSubkey tf st (r `div` 4)
  getElems st
  where
    nw = tfNw tf
    rounds = tfRounds tf
    unpermute st scratch = do
      forM_ [0 .. nw - 1] $ \i -> readArray st i >>= writeArray scratch (tfPerm tf ! i)
      forM_ [0 .. nw - 1] $ \i -> readArray scratch i >>= writeArray st i

-- ---------------------------------------------------------------------------
-- Byte/word conversion (little-endian) and the public block API.
-- ---------------------------------------------------------------------------

bytesToWords :: ByteString -> [Word64]
bytesToWords bs = [ word off | off <- [0, 8 .. BS.length bs - 8] ]
  where
    word off = go 0 0
      where
        go !k !acc
          | k == 8    = acc
          | otherwise = go (k + 1)
                           (acc .|. (fromIntegral (BS.index bs (off + k)) `shiftL` (8 * k)))

wordsToBytes :: [Word64] -> ByteString
wordsToBytes = BS.pack . concatMap toLE
  where
    toLE w = [ fromIntegral (w `shiftR` (8 * k)) .&. 0xff | k <- [0 .. 7] ] :: [Word8]

-- | Encrypt one block (exactly 'blockSize' bytes) in place.
encryptBlock :: Threefish -> ByteString -> ByteString
encryptBlock tf = wordsToBytes . encryptWords tf . bytesToWords

-- | Decrypt one block (exactly 'blockSize' bytes).
decryptBlock :: Threefish -> ByteString -> ByteString
decryptBlock tf = wordsToBytes . decryptWords tf . bytesToWords

-- ---------------------------------------------------------------------------
-- CTR mode: encrypt successive counter blocks (the IV as a big-endian counter)
-- and xor the keystream into the data. Encryption and decryption are the same.
-- ---------------------------------------------------------------------------

-- | Apply CTR keystream to @dat@ starting from counter @iv@ (one block wide).
-- The same call encrypts and decrypts.
ctrApply :: Threefish -> ByteString -> ByteString -> ByteString
ctrApply tf iv dat = BS.concat (go iv dat)
  where
    bs = tfNw tf * 8
    go counter d
      | BS.null d = []
      | otherwise =
          let ks = encryptBlock tf counter
              n = min bs (BS.length d)
              chunk = BS.take n d
              out = BS.pack (BS.zipWith xor chunk (BS.take n ks))
          in out : go (ctrIncrement counter) (BS.drop n d)

-- | Increment a counter block by one, treating it as a big-endian integer and
-- wrapping on overflow. The counter is public, so this branch is not secret.
ctrIncrement :: ByteString -> ByteString
ctrIncrement = BS.pack . reverse . inc . reverse . BS.unpack
  where
    inc [] = []
    inc (x : xs)
      | x' /= 0   = x' : xs
      | otherwise = x' : inc xs
      where x' = x + 1
