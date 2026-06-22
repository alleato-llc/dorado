-- | Tests for the Haskell port. Currently: Threefish known-answer vectors
-- (official Crypto++ threefish.txt values) and CTR self-consistency. A plain
-- assertion harness, exiting non-zero on any failure (no test-framework dep).
module Main (main) where

import Data.Char (digitToInt, isHexDigit)
import Data.IORef (modifyIORef', newIORef, readIORef)
import Data.Word (Word8)
import System.Exit (exitFailure)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

import Dorado.Threefish

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

  n <- readIORef fails
  if n == 0
    then putStrLn "\nall passed"
    else putStrLn ("\n" ++ show n ++ " FAILED") >> exitFailure
