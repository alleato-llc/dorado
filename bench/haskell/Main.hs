-- Haskell throughput runner. Times the from-scratch primitives under the uniform
-- protocol (see ../README.md) and emits one JSON line per benchmark. Compiled directly
-- against the port's library sources (-i../../haskell/src), so it needs only the GHC
-- boot packages the primitives use (bytestring, array) — not crypton, which only the
-- KDF/MAC modules pull in.
--
-- Laziness is the hazard here: a thunk returned and never inspected measures nothing.
-- Every op therefore forces its result with `evaluate` and returns a byte, which the
-- loop accumulates, so the work cannot be deferred, shared, or dropped.
{-# LANGUAGE BangPatterns #-}

module Main (main) where

import Control.Exception (evaluate)
import Data.Bits (xor)
import Data.List (sort)
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import Data.Word (Word64, Word8)
import GHC.Clock (getMonotonicTime)
import System.Environment (getArgs)
import Text.Printf (printf)

import qualified Dorado.Blake3 as Blake3
import qualified Dorado.Skein as Skein
import Dorado.Threefish (Variant (..), ctrApply, newThreefish)

-- | The Gota protocol these runners implement (see bench/README.md).
protocolVersion :: String
protocolVersion = "1.2.0"

data Op = Ctr Variant | SkeinHash | Blake3Hash

-- | One unit of measured work. Returns a byte of the result so the caller can keep it
-- alive; `evaluate` forces the strict ByteString, which is the whole computation.
runOp :: Op -> ByteString -> ByteString -> ByteString -> IO Word8
runOp op key iv dat = case op of
  Ctr v -> do
    let tf = newThreefish v key (BS.replicate 16 0)
    out <- evaluate (ctrApply tf iv dat)
    pure (BS.head out)
  SkeinHash -> do
    out <- evaluate (Skein.hash 32 dat)
    pure (BS.head out)
  Blake3Hash -> do
    out <- evaluate (Blake3.hash 32 dat)
    pure (BS.head out)

-- | Run the op @count@ times, xor-ing each result byte into an accumulator so nothing
-- can be optimized away, and return the elapsed seconds.
timeBatch :: Op -> ByteString -> ByteString -> ByteString -> Word64 -> IO Double
timeBatch op key iv dat count = do
  start <- getMonotonicTime
  let go !i !acc
        | i >= count = pure acc
        | otherwise = do
            b <- runOp op key iv dat
            go (i + 1) (acc `xor` b)
  !sink <- go 0 0
  end <- getMonotonicTime
  -- `sink` is consumed by the seq below purely to keep it from being discarded.
  sink `seq` pure (end - start)

-- | Grow the batch until one clears 100 ms, so the clock's resolution is noise.
growBatch :: Op -> ByteString -> ByteString -> ByteString -> Word64 -> IO Word64
growBatch op key iv dat batch = do
  elapsed <- timeBatch op key iv dat batch
  if elapsed >= 0.1 then pure batch else growBatch op key iv dat (batch * 2)

-- | Report peak throughput across many batches (the max MB/s is the reproducible rate;
-- jitter only ever slows a batch). The clock is read only at batch boundaries.
bench :: String -> Op -> ByteString -> ByteString -> ByteString -> Double -> Double -> IO ()
bench name op key iv dat warmup measure = do
  warmStart <- getMonotonicTime
  let warmLoop = do
        now <- getMonotonicTime
        if now - warmStart < warmup
          then runOp op key iv dat >> warmLoop
          else pure ()
  warmLoop

  batch <- growBatch op key iv dat 1

  t0 <- getMonotonicTime
  let bytes = fromIntegral (BS.length dat) :: Double
      -- Accumulate every batch's rate; the median beside the peak is the run's
      -- stability signal (protocol 1.1.0).
      loop !best !total acc = do
        now <- getMonotonicTime
        if now - t0 >= measure
          then pure (best, total, acc)
          else do
            elapsed <- timeBatch op key iv dat batch
            let mbps = bytes * fromIntegral batch / 1e6 / elapsed
            loop (max best mbps) (total + batch) (mbps : acc)
  (best, total, samples) <- loop 0 0 []

  let sorted = sort samples
      n = length sorted
      median
        | n == 0 = 0
        | odd n = sorted !! (n `div` 2)
        | otherwise = (sorted !! (n `div` 2 - 1) + sorted !! (n `div` 2)) / 2

  printf
    "{\"impl\":\"haskell\",\"bench\":\"%s\",\"mbps\":%.2f,\"mbps_median\":%.2f,\"iters\":%d,\"protocol\":\"%s\"}\n"
    name
    best
    median
    (toInteger total)
    protocolVersion

main :: IO ()
main = do
  args <- getArgs
  let n = case args of
        (a : _) -> read a :: Int
        _ -> 1048576
      warmup = case args of
        (_ : b : _) -> read b :: Double
        _ -> 0.5
      measure = case args of
        (_ : _ : c : _) -> read c :: Double
        _ -> 2.0

      dat = BS.replicate n 0
      key = BS.replicate 128 7
      iv = BS.replicate 128 1

  -- Each variant takes a key of its own width; the CTR IV is one block wide.
  bench "threefish-256-ctr" (Ctr TF256) (BS.take 32 key) (BS.take 32 iv) dat warmup measure
  bench "threefish-512-ctr" (Ctr TF512) (BS.take 64 key) (BS.take 64 iv) dat warmup measure
  bench "threefish-1024-ctr" (Ctr TF1024) (BS.take 128 key) (BS.take 128 iv) dat warmup measure
  bench "skein-512" SkeinHash key iv dat warmup measure
  bench "blake3" Blake3Hash key iv dat warmup measure
