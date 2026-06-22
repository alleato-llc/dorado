-- | Tests for the Haskell port. Currently: Threefish known-answer vectors
-- (official Crypto++ threefish.txt values) and CTR self-consistency. A plain
-- assertion harness, exiting non-zero on any failure (no test-framework dep).
module Main (main) where

import Data.Char (digitToInt, intToDigit, isHexDigit)
import Data.IORef (modifyIORef', newIORef, readIORef)
import Data.Word (Word8)
import System.Exit (exitFailure)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.ByteString (ByteString)

import Dorado.Threefish
import qualified Dorado.Skein as Skein
import qualified Dorado.Blake3 as Blake3

-- Official BLAKE3 test-vector input convention: byte i = i mod 251.
seqBytes :: Int -> ByteString
seqBytes n = BS.pack [ fromIntegral (i `mod` 251) | i <- [0 .. n - 1] ]

toHex :: ByteString -> String
toHex = concatMap byte . BS.unpack
  where byte b = [ intToDigit (fromIntegral b `div` 16), intToDigit (fromIntegral b `mod` 16) ]

unhex :: String -> ByteString
unhex = BS.pack . go . filter isHexDigit
  where
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go _              = []

tweak :: ByteString
tweak = unhex "000102030405060708090A0B0C0D0E0F"

main :: IO ()
main = do
  fails <- newIORef (0 :: Int)
  let check name ok =
        if ok
          then putStrLn ("ok   " ++ name)
          else putStrLn ("FAIL " ++ name) >> modifyIORef' fails (+ 1)

  -- Threefish known-answer vectors (encrypt matches, decrypt round-trips).
  let kat name v key pt ct =
        let c = newThreefish v (unhex key) tweak
            p = unhex pt
            e = unhex ct
        in do
          check (name ++ " encrypt") (encryptBlock c p == e)
          check (name ++ " decrypt") (decryptBlock c e == p)

  kat "threefish256" TF256
    "101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F"
    "FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0"
    "E0D091FF0EEA8FDFC98192E62ED80AD59D865D08588DF476657056B5955E97DF"

  kat "threefish512" TF512
    ("101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F" ++
     "303132333435363738393A3B3C3D3E3F4041424344454647 48494A4B4C4D4E4F")
    ("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" ++
     "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0")
    ("E304439626D45A2CB401CAD8D636249A6338330EB06D45DD8B36B90E97254779" ++
     "272A0A8D99463504784420EA18C9A725AF11DFFEA10162348927673D5C1CAF3D")

  kat "threefish1024" TF1024
    ("101112131415161718191A1B1C1D1E1F2021222324252627 28292A2B2C2D2E2F" ++
     "303132333435363738393A3B3C3D3E3F4041424344454647 48494A4B4C4D4E4F" ++
     "505152535455565758595A5B5C5D5E5F6061626364656667 68696A6B6C6D6E6F" ++
     "707172737475767778797A7B7C7D7E7F8081828384858687 88898A8B8C8D8E8F")
    ("FFFEFDFCFBFAF9F8F7F6F5F4F3F2F1F0EFEEEDECEBEAE9E8E7E6E5E4E3E2E1E0" ++
     "DFDEDDDCDBDAD9D8D7D6D5D4D3D2D1D0CFCECDCCCBCAC9C8C7C6C5C4C3C2C1C0" ++
     "BFBEBDBCBBBAB9B8B7B6B5B4B3B2B1B0AFAEADACABAAA9A8A7A6A5A4A3A2A1A0" ++
     "9F9E9D9C9B9A99989796959493929190 8F8E8D8C8B8A89888786858483828180")
    ("A6654DDBD73CC3B05DD777105AA849BCE49372EAAFFC5568D254771BAB85531C" ++
     "94F780E7FFAAE430D5D8AF8C70EEBBE1760F3B42B737A89CB363490D670314BD" ++
     "8AA41EE63C2E1F45FBD477922F8360B388D6125EA6C7AF0AD7056D01796E90C8" ++
     "3313F4150A5716B30ED5F569288AE974CE2B4347926FCE57DE44512177DD7CDE")

  -- CTR self-consistency (no official vectors): the first keystream block must
  -- equal encrypt_block(iv), and apply-twice must round-trip at an awkward length.
  let c = newThreefish TF256 (unhex (replicate 64 '1')) tweak
      iv = BS.replicate 32 0x22
      msg = BS.pack ([0 .. 199] :: [Word8])
      ks0 = BS.take 32 (ctrApply c iv (BS.replicate 32 0))
  check "ctr keystream block 0 == encrypt(iv)" (ks0 == encryptBlock c iv)
  check "ctr round-trips at 200 bytes" (ctrApply c iv (ctrApply c iv msg) == msg)

  -- Skein-512 known-answer vectors, captured from the Rust reference (gyotaku).
  check "skein512-256 empty"
    (toHex (Skein.hash 32 BS.empty)
       == "39ccc4554a8b31853b9de7a1fe638a24cce6b35a55f2431009e18780335d2621")
  check "skein512-256 abc"
    (toHex (Skein.hash 32 (C8.pack "abc"))
       == "0977b339c3c85927071805584d5460d8f20da8389bbe97c59b1cfac291fe9527")
  check "skein512-256 'a'*100 (multi-block)"
    (toHex (Skein.hash 32 (BS.replicate 100 0x61))
       == "933bd28877ef7215ae7d4fd99da95a995cd5555077526c3bc395ad1f1d6bb0fa")
  check "skein512-512 abc"
    (toHex (Skein.hash 64 (C8.pack "abc"))
       == "8f5dd9ec798152668e35129496b029a960c9a9b88662f7f9482f110b31f9f938"
       ++ "93ecfb25c009baad9e46737197d5630379816a886aa05526d3a70df272d96e75")

  -- MAC: an empty key is identical to the unkeyed hash; a real key differs.
  check "skein-mac empty key == hash"
    (Skein.mac BS.empty 32 (C8.pack "abc") == Skein.hash 32 (C8.pack "abc"))
  check "skein-mac with key differs"
    (Skein.mac (C8.pack "key") 32 (C8.pack "abc") /= Skein.hash 32 (C8.pack "abc"))

  -- BLAKE3 known-answer vectors, captured from the Rust reference (and matching
  -- the official BLAKE3 vectors). Inputs use byte i = i mod 251.
  check "blake3 empty"
    (toHex (Blake3.hash 32 BS.empty)
       == "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262")
  check "blake3 abc"
    (toHex (Blake3.hash 32 (C8.pack "abc"))
       == "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85")
  check "blake3 1024 bytes (one full chunk)"
    (toHex (Blake3.hash 32 (seqBytes 1024))
       == "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7")
  check "blake3 1025 bytes (two chunks, parent node)"
    (toHex (Blake3.hash 32 (seqBytes 1025))
       == "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444")
  check "blake3 abc XOF 64 bytes"
    (toHex (Blake3.hash 64 (C8.pack "abc"))
       == "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d85"
       ++ "1fb250ae7393f5d02813b65d521a0d492d9ba09cf7ce7f4cffd900f23374bf0b")
  check "blake3 keyed mac (key = 0..31, msg abc)"
    (toHex (Blake3.keyedMac (BS.pack [0 .. 31]) 32 (C8.pack "abc"))
       == "6da54495d8152f2bcba87bd7282df70901cdb66b4448ed5f4c7bd2852b8b5532")

  n <- readIORef fails
  if n == 0
    then putStrLn "\nall passed"
    else putStrLn ("\n" ++ show n ++ " FAILED") >> exitFailure
