-- | Tests for the Haskell port. Currently: Threefish known-answer vectors
-- (official Crypto++ threefish.txt values) and CTR self-consistency. A plain
-- assertion harness, exiting non-zero on any failure (no test-framework dep).
module Main (main) where

import Data.Char (digitToInt, intToDigit, isHexDigit)
import Data.Bits (xor)
import Data.Either (isLeft)
import Data.IORef (modifyIORef', newIORef, readIORef)
import Data.List (nub)
import Data.Word (Word8, Word32)
import System.Exit (exitFailure)
import System.IO (IOMode (ReadMode, WriteMode), withFile)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.ByteString (ByteString)

import Dorado.Format (Header (..), serializeHeader)
import Dorado.Threefish
import qualified Dorado.Skein as Skein
import qualified Dorado.Blake3 as Blake3
import qualified Dorado.Sha256 as Sha256
import qualified Dorado.Kdf as Kdf
import qualified Dorado.Mac as Mac
import qualified Dorado.Engine as Engine

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

  -- Incremental Skein (used by gyotaku streaming) matches the one-shot hash at
  -- any chunking, including block-boundary splits.
  let incrMsg = seqBytes 700
      oneShot = Skein.hash 32 incrMsg
      chunked step b = [BS.take step (BS.drop i b) | i <- [0, step .. BS.length b - 1]]
  check "incremental skein == one-shot (various chunkings)"
    (all (\step -> Skein.finalize (foldl' Skein.update (Skein.newHasher 32) (chunked step incrMsg)) == oneShot)
         [1, 7, 63, 64, 65, 200, 700])

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

  -- SHA-256 (FIPS 180-4) and HMAC-SHA256 (RFC 4231) standard vectors.
  check "sha256 empty"
    (toHex (Sha256.sha256 BS.empty)
       == "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
  check "sha256 abc"
    (toHex (Sha256.sha256 (C8.pack "abc"))
       == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
  check "sha256 56-byte (two blocks)"
    (toHex (Sha256.sha256 (C8.pack "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
       == "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
  check "hmac-sha256 RFC4231 TC1"
    (toHex (Sha256.hmacSha256 (BS.replicate 20 0x0b) (C8.pack "Hi There"))
       == "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
  check "hmac-sha256 RFC4231 TC2"
    (toHex (Sha256.hmacSha256 (C8.pack "Jefe") (C8.pack "what do ya want for nothing?"))
       == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
  check "hmac-sha256 RFC4231 TC6 (key > 64 bytes)"
    (toHex (Sha256.hmacSha256 (BS.replicate 131 0xaa)
              (C8.pack "Test Using Larger Than Block-Size Key - Hash Key First"))
       == "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")

  -- KDF delegation (crypton). scrypt and PBKDF2-HMAC-SHA256 vectors from RFC 7914;
  -- Argon2id is validated end-to-end via the container cross-compat tests.
  check "scrypt RFC7914 (N=16,r=1,p=1, empty)"
    (toHex (Kdf.derive (Kdf.Scrypt 4 1 1) BS.empty BS.empty 64)
       == "77d6576238657b203b19ca42c18a0497f16b4844e3074ae8dfdffa3fede21442"
       ++ "fcd0069ded0948f8326a753a0fc81f17e8d3e0fb2e0d3628cf35e20c38d18906")
  check "pbkdf2-hmac-sha256 RFC7914 (passwd/salt, c=1)"
    (toHex (Kdf.derive (Kdf.Pbkdf2 1) (C8.pack "passwd") (C8.pack "salt") 64)
       == "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc"
       ++ "49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")

  -- KDF cost validation (Kdf.validate): sane and edge-exact parameters pass,
  -- each individual absurd knob is rejected. Bounds match the other ports.
  check "kdf validate accepts sane defaults"
    (Kdf.validate (Kdf.Argon2id 65536 3 1) == Right ()
       && Kdf.validate (Kdf.Scrypt 15 8 1) == Right ()
       && Kdf.validate (Kdf.Pbkdf2 600000) == Right ())
  check "kdf validate bounds are edge-exact"
    (Kdf.validate (Kdf.Argon2id (2 ^ (21 :: Int)) 64 16) == Right ()
       && Kdf.validate (Kdf.Scrypt 21 32 16) == Right ()
       && Kdf.validate (Kdf.Pbkdf2 50000000) == Right ())
  check "argon2 m_cost bound" (isLeft (Kdf.validate (Kdf.Argon2id (2 ^ (21 :: Int) + 1) 3 1)))
  check "argon2 t_cost bound" (isLeft (Kdf.validate (Kdf.Argon2id 1024 65 1)))
  check "argon2 p_cost bound" (isLeft (Kdf.validate (Kdf.Argon2id 1024 3 17)))
  check "scrypt log_n bound" (isLeft (Kdf.validate (Kdf.Scrypt 22 8 1)))
  check "scrypt r bound" (isLeft (Kdf.validate (Kdf.Scrypt 15 33 1)))
  check "scrypt p bound" (isLeft (Kdf.validate (Kdf.Scrypt 15 8 17)))
  check "pbkdf2 zero rounds rejected" (isLeft (Kdf.validate (Kdf.Pbkdf2 0)))
  check "pbkdf2 rounds bound" (isLeft (Kdf.validate (Kdf.Pbkdf2 50000001)))

  -- Chunk-size cap resolution (pure, no environment): the default, tightening,
  -- clamping into (0, 1 GiB], and fallback on unparseable overrides.
  check "chunk cap defaults to 64 MiB when unset" (Engine.chunkCapFrom Nothing == 64 * 1024 * 1024)
  check "chunk cap override tightens" (Engine.chunkCapFrom (Just "1024") == 1024)
  check "chunk cap trims whitespace" (Engine.chunkCapFrom (Just " 4096 ") == 4096)
  check "chunk cap clamps zero up to one" (Engine.chunkCapFrom (Just "0") == 1)
  check "chunk cap clamps to the 1 GiB ceiling"
    (Engine.chunkCapFrom (Just "2147483648") == 1024 * 1024 * 1024)
  check "chunk cap falls back on garbage" (Engine.chunkCapFrom (Just "lots") == 64 * 1024 * 1024)
  check "chunk cap falls back on numbers past 32 bits"
    (Engine.chunkCapFrom (Just "5000000000") == 64 * 1024 * 1024)

  -- Key-based derivation (deriveFromKey / deriveFromKeyWith): known-answer
  -- vectors from ../docs/fixtures/derive-from-key.md (generated by the Rust
  -- reference), then the determinism and separation properties.
  let kdkKey = unhex "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
  check "deriveFromKey KAT skein_32key_enc_32out"
    (toHex (Kdf.deriveFromKey kdkKey "dorado/fixture/enc" 32)
       == "b638c503342dbd51bdfa8906b1cc6b18d7e54252b95e460c522ab3cd939802c6")
  check "deriveFromKey KAT skein_32key_mac_64out"
    (toHex (Kdf.deriveFromKey kdkKey "dorado/fixture/mac" 64)
       == "6ae3f6f7518e9a4c8a7be8269deb848186beb64b5b43f0bafef81bce4b27d40e"
       ++ "f227e2064b941069cc6225cad0a39fcc22aba08fb87f3ba8aacdf4b70b100da6")
  check "deriveFromKey KAT skein_16key_enc_32out"
    (toHex (Kdf.deriveFromKey (unhex "a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5") "dorado/fixture/enc" 32)
       == "3990e038c7235e62480afe99712203225194afb93910df4101447098e630d0e4")
  check "deriveFromKey KAT skein_32key_empty_domain_32out"
    (toHex (Kdf.deriveFromKey kdkKey "" 32)
       == "5bba4214745b3932c1fc620c660b60a4058613ff2bd9d80224d472cd810f7a99")
  check "deriveFromKeyWith KAT blake3_32key_enc_32out"
    (fmap toHex (Kdf.deriveFromKeyWith Kdf.Blake3 kdkKey "dorado/fixture/enc" 32)
       == Right "8266bd0cfb0d73715aa841fe008c311a44d6b36e0aa01b94f13a90783fe62e1d")
  check "deriveFromKeyWith KAT blake3_32key_mac_64out"
    (fmap toHex (Kdf.deriveFromKeyWith Kdf.Blake3 kdkKey "dorado/fixture/mac" 64)
       == Right ("ea38a1780192707518d15003262a66c245680a579762a7d863cc33078f2f6eaa"
                 ++ "9a5086f70d00eb7c6cd12fdc7872e5a2023e63c28087631ce835d7e9c7264290"))
  let master = BS.replicate 32 0x42
  check "deriveFromKey deterministic, domain- and key-separated"
    (Kdf.deriveFromKey master "myapp/index" 32 == Kdf.deriveFromKey master "myapp/index" 32
       && Kdf.deriveFromKey master "myapp/index" 32 /= Kdf.deriveFromKey master "myapp/data" 32
       && Kdf.deriveFromKey master "myapp/index" 32 /= Kdf.deriveFromKey (BS.replicate 32 0x43) "myapp/index" 32
       && Kdf.deriveFromKey master "myapp/index" 32 /= master)
  check "deriveFromKey default == deriveFromKeyWith Skein512"
    (Kdf.deriveFromKeyWith Kdf.Skein512 master "myapp/index" 32
       == Right (Kdf.deriveFromKey master "myapp/index" 32))
  check "skein output length is part of the config, not a truncation"
    (BS.take 32 (Kdf.deriveFromKey master "myapp/index" 128) /= Kdf.deriveFromKey master "myapp/index" 32)
  check "blake3 fan-out deterministic, domain-separated, distinct from skein"
    (Kdf.deriveFromKeyWith Kdf.Blake3 master "myapp/index" 32 == Kdf.deriveFromKeyWith Kdf.Blake3 master "myapp/index" 32
       && Kdf.deriveFromKeyWith Kdf.Blake3 master "myapp/index" 32 /= Kdf.deriveFromKeyWith Kdf.Blake3 master "myapp/data" 32
       && Kdf.deriveFromKeyWith Kdf.Blake3 master "myapp/index" 32 /= Kdf.deriveFromKeyWith Kdf.Skein512 master "myapp/index" 32)
  check "blake3 is an XOF: shorter output is a prefix of longer"
    (fmap (BS.take 32) (Kdf.deriveFromKeyWith Kdf.Blake3 master "myapp/index" 128)
       == Kdf.deriveFromKeyWith Kdf.Blake3 master "myapp/index" 32)
  check "blake3 fan-out rejects a non-32-byte key"
    (isLeft (Kdf.deriveFromKeyWith Kdf.Blake3 (BS.replicate 16 0) "myapp/index" 32))

  -- MAC dispatch: every option yields a 32-byte tag; the three differ for the
  -- same key/message. (Each delegates to an already-verified primitive; the
  -- container cross-compat tests pin the exact bytes end-to-end.)
  let mkey = BS.replicate 32 0x5a
      mmsg = C8.pack "frame contents"
      tags = [ Mac.tag m mkey mmsg | m <- [Mac.HmacSha256, Mac.Skein512, Mac.Blake3Keyed] ]
  check "mac tags are all 32 bytes" (all ((== 32) . BS.length) tags)
  check "mac tags differ by algorithm" (length (nub tags) == 3)
  check "mac skein512 == primitive keyed skein" (Mac.tag Mac.Skein512 mkey mmsg == Skein.mac mkey 32 mmsg)

  -- Container cross-compatibility: decrypt .mahi files produced by the Rust CLI,
  -- covering every KDF, MAC, both variants, a multi-frame file, and a labeled one.
  let pw = C8.pack "correct horse battery staple"
      pt1 = C8.pack "Attack at dawn. Meet by the old oak."
      decFix name expected = do
        bytes <- BS.readFile ("test/fixtures/" ++ name)
        check ("decrypt rust fixture " ++ name) (Engine.decryptPassword pw bytes == Right expected)
  decFix "pbkdf2-skein-256.mahi" pt1
  decFix "scrypt-hmac-256.mahi" pt1
  decFix "argon2-blake3-256.mahi" pt1
  decFix "pbkdf2-skein-512.mahi" pt1
  decFix "labeled.mahi" pt1
  decFix "multichunk.mahi" (seqBytes 3000)

  -- Wrong password and tampering are rejected.
  fix <- BS.readFile "test/fixtures/pbkdf2-skein-256.mahi"
  check "wrong password rejected" (isLeft (Engine.decryptPassword (C8.pack "wrong") fix))
  let tampered = BS.concat [BS.init fix, BS.singleton (BS.last fix `xor` 1)]
  check "tampered tag rejected" (isLeft (Engine.decryptPassword pw tampered))

  -- Hardening: hostile KDF costs or an absurd chunk size in the (untrusted)
  -- header are rejected before any derivation or allocation. The Argon2 header
  -- asks for 2^30 KiB (1 TiB) of memory; the test finishing at all is the
  -- proof that no derivation was attempted.
  let hostileHeader kdf cs =
        serializeHeader
          (Header 4 TF256 kdf Mac.Skein512 cs (BS.replicate 16 0x01) (BS.replicate 16 0x02) (BS.replicate 32 0x03) BS.empty)
  check "hostile argon2 m_cost rejected before deriving"
    (Engine.decryptPassword pw (hostileHeader (Kdf.Argon2id (2 ^ (30 :: Int)) 3 1) 65536)
       == Left "argon2 memory cost too large")
  check "hostile scrypt log_n rejected before deriving"
    (Engine.decryptPassword pw (hostileHeader (Kdf.Scrypt 40 8 1) 65536)
       == Left "scrypt cost (log2 N) too large")
  check "hostile pbkdf2 rounds rejected before deriving"
    (Engine.decryptPassword pw (hostileHeader (Kdf.Pbkdf2 4000000000) 65536)
       == Left "pbkdf2 rounds too large")
  check "over-cap chunk size in header rejected (64 MiB default cap)"
    (Engine.decryptPassword pw (hostileHeader (Kdf.Pbkdf2 1000) (128 * 1024 * 1024))
       == Left "invalid chunk size 134217728 in header")
  check "zero chunk size in header rejected"
    (Engine.decryptPassword pw (hostileHeader (Kdf.Pbkdf2 1000) 0)
       == Left "invalid chunk size 0 in header")
  check "non-block-multiple chunk size in header rejected"
    (Engine.decryptPassword pw (hostileHeader (Kdf.Pbkdf2 1000) 65535)
       == Left "invalid chunk size 65535 in header")

  -- The streaming decrypt path runs the same bounds before deriving.
  let hostileF = "/tmp/dorado-hs-hostile"
      hostileOutF = "/tmp/dorado-hs-hostile-out"
  BS.writeFile hostileF (hostileHeader (Kdf.Argon2id (2 ^ (30 :: Int)) 3 1) 65536)
  hres <- withFile hostileF ReadMode $ \hin -> withFile hostileOutF WriteMode $ \hout ->
    Engine.decryptPasswordStream pw Nothing hin hout
  check "stream decrypt rejects hostile argon2 costs before deriving"
    (hres == Left "argon2 memory cost too large")

  -- Haskell encrypt -> Haskell decrypt round-trips (fast KDF), across variants,
  -- MACs, and a multi-frame file.
  let baseOpts = Engine.defaultOptions { Engine.optKdf = Kdf.Pbkdf2 1000 }
      salt = BS.replicate 16 0x01
      rtweak = BS.replicate 16 0x02
      iv32 = BS.replicate 32 0x03
      roundTrip rname opts riv rmsg =
        check ("round-trip " ++ rname)
          (Engine.decryptPassword pw (Engine.encryptPasswordWith opts salt rtweak riv pw rmsg) == Right rmsg)
  roundTrip "pbkdf2/skein/256" baseOpts iv32 pt1
  roundTrip "hmac-sha256" baseOpts { Engine.optMac = Mac.HmacSha256 } iv32 pt1
  roundTrip "blake3-keyed" baseOpts { Engine.optMac = Mac.Blake3Keyed } iv32 pt1
  roundTrip "variant-512" baseOpts { Engine.optVariant = TF512 } (BS.replicate 64 0x03) pt1
  roundTrip "multi-frame (64B chunks)" baseOpts { Engine.optChunkSize = 64 } iv32 (seqBytes 200)
  roundTrip "empty plaintext" baseOpts iv32 BS.empty

  -- Streaming (Handle-based, constant memory) must produce identical bytes to the
  -- in-memory form and round-trip, across multiple frames.
  let sopts = baseOpts { Engine.optChunkSize = 64 }
      sbig = seqBytes 500
      bytesOut = Engine.encryptPasswordWith sopts salt rtweak iv32 pw sbig
      ptF = "/tmp/dorado-hs-st-pt"
      ctF = "/tmp/dorado-hs-st-ct"
      outF = "/tmp/dorado-hs-st-out"
  BS.writeFile ptF sbig
  withFile ptF ReadMode $ \hin -> withFile ctF WriteMode $ \hout ->
    Engine.encryptPasswordStream sopts salt rtweak iv32 pw hin hout
  streamOut <- BS.readFile ctF
  check "stream encrypt == in-memory encrypt" (streamOut == bytesOut)
  res <- withFile ctF ReadMode $ \hin -> withFile outF WriteMode $ \hout ->
    Engine.decryptPasswordStream pw Nothing hin hout
  streamDec <- BS.readFile outF
  check "stream decrypt round-trips (multi-frame)" (res == Right () && streamDec == sbig)

  -- Raw-key authenticated mode: known-answer vectors from the Rust reference
  -- (../docs/fixtures/raw-authenticated.md), hardcoded byte-for-byte in both
  -- directions. This is the actual cross-language compatibility proof.
  let rawKat name variant macv chunkKib keyHex ivHex tweakHex ptHex ctHex =
        let rkey = unhex keyHex
            riv = unhex ivHex
            rtw = unhex tweakHex
            rpt = unhex ptHex
            rct = unhex ctHex
            chunkSize = chunkKib * 1024 :: Word32
         in do
              check (name ++ " encrypt matches") (Engine.encryptRawAuthenticated variant rkey rtw riv macv chunkSize rpt == Right rct)
              check (name ++ " decrypt matches") (Engine.decryptRawAuthenticated variant rkey rtw riv macv chunkSize rct == Right rpt)

  rawKat "t256_skein_single" TF256 Mac.Skein512 64
    "1111111111111111111111111111111111111111111111111111111111111111"
    "0202020202020202020202020202020202020202020202020202020202020202"
    "00000000000000000000000000000000"
    "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c616e677561676573"
    "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b8961a7bb9296d0da601e3aba580a70532ad6b83e8fc1050620de95d5ba50e545621"

  rawKat "t256_hmac_single" TF256 Mac.HmacSha256 64
    "1111111111111111111111111111111111111111111111111111111111111111"
    "0202020202020202020202020202020202020202020202020202020202020202"
    "00000000000000000000000000000000"
    "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c616e677561676573"
    "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b8968381b4daded95b311377792e768eee91a63e2346b585ac3eda337afd6ed6dfff"

  rawKat "t256_blake3_single" TF256 Mac.Blake3Keyed 64
    "1111111111111111111111111111111111111111111111111111111111111111"
    "0202020202020202020202020202020202020202020202020202020202020202"
    "00000000000000000000000000000000"
    "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c616e677561676573"
    "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b896815761a7e9f6762a4a0dd0de969ab2bf00e7d04304b45fb53984b5e29deb9834"

  rawKat "t512_skein_single" TF512 Mac.Skein512 64
    "11111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "02020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
    "00000000000000000000000000000000"
    "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c616e677561676573"
    "010000003e9b6cf38a329d996ff458a80a5993a2fbbb8b29237d5561b5a7883b2b47eb06ca7ea842953feb5ebf6aec6b95d17c646a8294b66e6f04a98ffc255ee4e62d44f0b6fa861dc2ea6a8be5fd71b60863900177af52c649ede00952bde11f1394"

  rawKat "t1024_skein_single" TF1024 Mac.Skein512 64
    "1111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111111"
    "0202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202020202"
    "00000000000000000000000000000000"
    "65786572636973696e6720746865207261772061757468656e7469636174656420636f6e737472756374696f6e206163726f7373206c616e677561676573"
    "010000003ef55cd4e609b16c109712985cc509501cd194befaa963a620c123816bd9fd494f85cd899f2a52b005a0fb1105fe6706ceb7f937573662a11b14b53c939c8ade26889e72113babe3236093b8855432a67c45888b131be41f72cd890a724f0f"

  rawKat "t256_skein_multichunk" TF256 Mac.Skein512 1
    "1111111111111111111111111111111111111111111111111111111111111111"
    "0202020202020202020202020202020202020202020202020202020202020202"
    "00000000000000000000000000000000"
    "61206c6f6e676572207061796c6f6164206d65616e7420746f207370616e206d756c7469706c65206f6e652d6b696c6f627974652061757468656e74696361746564206368756e6b7320736f207468652063726f73732d6c616e6775616765206669787475726520616c736f206578657263697365732074686520636f6e74696e756f757320636f756e74657220616e64207065722d6672616d652074616767696e67206163726f7373206368756e6b20626f756e6461726965732c206e6f74206a75737420612073696e676c65206672616d652e20787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878787878"
    "0000000400f22a092b48a93449b906d28f4e1d30649ff11c6761b40436f8837cfa9715f834310c46654feabc437288741b5f16b5ff8bab79018d524a3a5bc2f307b486959bdb2b43f608b3a624af1d302506d312ff8c536eee10f553ab87e39697249ea5f92050c9ee832a8c8c2d7e4dffba0d5b3650a65d4ec8ef92c6ec60d2030c334e56e091654db2e1ad8e3cbc921f7092bc34afc8d41226526e31b1da8240da06169ef5643695b82247984b334e4842a34b88789ff0886098e002521245065ba7e1550136a7817ed24f451cc0a1f8c778dbc3febc1e0de9fd4810f7077c85a8ac7dd49b0c34546708ccba6babcc1391a2f0d2d0e44f848f5f8d894f48d2b2f0f8854bb6257179d883d55cf7b21c5c764fb1008f582917a6d54ddd75209c39814a1f0c795fcdcf11fb69fa36bbbdf9d798338cf01a20326fc4c4d9e0ce7d874cd0f6b5bc493dcfaac173f8259f597a1d28c72e92e2b47a7573857e0dd47b1ef6192b97434fdc7572f5ed93c4eee4b0466bed9246a037334cc319ab9d06830edccd3bca5ef2e69769a4d2a57b5d3cde17381ba1d5dee0f828ff67b0b31b1f78d6684a2ef8596c0cf60ba76834ce054fb4f7e524df218c21c2f552f74e445efbbc24c8b29df788c92b0c0a08251583fa6f0dbc187ff8dc11f572160e9f813aa04868a69ca4c0f8b111d5213ef4d7e7be43d34c4db41241764093e1f259ce6430b754aaeeaa5fd010334928380060453213fde390d7d1b36f0f34242b5856df0e13f6bcc351c557c3b4b0fb5db5382bf229818a094b9ad714d0d73ba734da002a4c1fdf9613c25556ed9cb350f1d17a863ddb72a13688f51e7e56f9f6d97fcf1b7f050c4a5f45c0760ae09f19fdccebc47d48cb6a22de0b2327a30f19038b2bf06e69e3229fd9db1b55dad18a30bc67f3b4670a35b9c17884feb94f6c7b1183faadb7c60768c34e098754d59ce4b057249e5a7e0fc37a84925d8582a996e3ff38a3e844711f444a8ad1bbcda549b9d3b3d1f1a1c436cca8bd093056207951372661e6f1d673d04279a7bbb35bccb5bc5b16053506d66c0171417a7428b40e117b21f20d73ffd4a0b4c31a8314fc41415f23ea59fb375e090a1442f3a99b46ffcb2db05ae459912ace292e382feddede89ce478b2f09072e8415442d5208e7be684406bcd8d1daf671471c875e9473d23be31ae5cb4dd59166fca876d33c1bc4354275ac62acc6e797e78c6255fc4aa500776fdd556364c98c0c0bdb00f897bdf6e782a74a65b67539a0b5d2d0d18fb3368d45913b2e1cac5e4b6c6c790c0327b2fd8569c1182a945859c9fed3e0009cf6067ff4910f6fab39d77d8da052a1aec80b115391f717475e9f8ab01ca3a2e7f4ed45e15cb8590c01f6274aae9b75e3852fce44b07f41bfe18777395112bbafbfab1be72df1be7a16e502d3385ff547f083bab16cd43d57f00d8fcce0595e3b57f18b2ca2da0f94f8c42bdc5237a41673617ea43d010000018657d51b2abd9a7809306c46b7c1020a729dd1efddc182b7412e45fae64f45b3e33ad6440f1d827977eb3f5b3e583d718a8c0fb43d4b00d557dc9a7afeef9a361a3a18014fa545baa6a184836a082798c4de40c82b96a5a5cd557fb4a8e15d6d0d5f411e6083b3f2c14b716c7a4d5167e077b1a2ded34f9e30eea332309801843ea53f53bea4f265ee8176a28c08b80f0189d754bef399ebd1c4407432af717dd7b949f8eee02cf4dca067b4b6cd7f50dd53b8bff3e35af9352d0d62b3ccf4d3f5af2eb8ed593200c1826984322967bf1bd6f682ff312690bf64c277bad2ab306931e97e23dd5790127921af7d16617456c585b835117b08621c40dddd38929d0728da224e31dd1d2d5461b2ce6e162f41436c92b5515223aa3f9572ab9ede606fb0c2c94545cc6221179aa6c11508e2dc6f1be11d8c82d051609ca26b397fffdbfd26d76301e1ecc03ab9699df7863eeee1a9bdd861c71319b3195e32215a56ada80234a28b8c31376c6846df120d9f0eb0979b618dd62b78e2fb886e7412cd9137451c75ace33797024dadf2784b969e1c56a81088dd5ac19c8a6061d2c9519c4309170d8192"

  -- Round-trip tests beyond the fixed KAT bytes: every MAC option, a
  -- non-256 variant, multi-frame chunking, and an empty payload.
  let rawRoundTrip name variant macv chunkSize key tw riv rpt =
        check ("raw-authenticated round-trip " ++ name)
          ( (Engine.encryptRawAuthenticated variant key tw riv macv chunkSize rpt
               >>= Engine.decryptRawAuthenticated variant key tw riv macv chunkSize)
              == Right rpt
          )
      rawKey256 = BS.replicate 32 0x11
      rawKey512 = BS.replicate 64 0x11
      rawTweak = BS.replicate 16 0x02
      rawIv256 = BS.replicate 32 0x03
      rawIv512 = BS.replicate 64 0x03
  rawRoundTrip "skein512" TF256 Mac.Skein512 65536 rawKey256 rawTweak rawIv256 pt1
  rawRoundTrip "hmac-sha256" TF256 Mac.HmacSha256 65536 rawKey256 rawTweak rawIv256 pt1
  rawRoundTrip "blake3-keyed" TF256 Mac.Blake3Keyed 65536 rawKey256 rawTweak rawIv256 pt1
  rawRoundTrip "variant-512" TF512 Mac.Skein512 65536 rawKey512 rawTweak rawIv512 pt1
  rawRoundTrip "multi-frame (64B chunks)" TF256 Mac.Skein512 64 rawKey256 rawTweak rawIv256 (seqBytes 200)
  rawRoundTrip "empty plaintext" TF256 Mac.Skein512 65536 rawKey256 rawTweak rawIv256 BS.empty

  -- Tamper detection, wrong key, and mismatched tweak/IV: all must be
  -- rejected with an auth-failure 'Left', using the t256_skein_single KAT
  -- vector's fixed ciphertext/tag. The tweak and IV are bound into frame 0's
  -- AAD (not just used for the keystream), so swapping either alone, holding
  -- ciphertext and tag fixed, must fail rather than silently produce
  -- different plaintext.
  let kKey = unhex "1111111111111111111111111111111111111111111111111111111111111111"
      kIv = unhex "0202020202020202020202020202020202020202020202020202020202020202"
      kTweak = unhex "00000000000000000000000000000000"
      kCt = unhex "010000003ef672003645a72252f71193824a177172deeb59677ab44c27f9d766e9970fbd3d64035d624cf2ab167e9278595a5fb8f39bbd7e178d5f5e2054d2fc14b8961a7bb9296d0da601e3aba580a70532ad6b83e8fc1050620de95d5ba50e545621"
      tamperedCt = BS.concat [BS.init kCt, BS.singleton (BS.last kCt `xor` 1)]
      wrongKey = BS.replicate 32 0x22
      wrongTweak = BS.replicate 16 0x99
      wrongIv = BS.replicate 32 0x77
      chunk64k = 65536 :: Word32
  check "raw-authenticated tampered ciphertext rejected"
    (isLeft (Engine.decryptRawAuthenticated TF256 kKey kTweak kIv Mac.Skein512 chunk64k tamperedCt))
  check "raw-authenticated wrong key rejected"
    (isLeft (Engine.decryptRawAuthenticated TF256 wrongKey kTweak kIv Mac.Skein512 chunk64k kCt))
  check "raw-authenticated wrong tweak rejected"
    (isLeft (Engine.decryptRawAuthenticated TF256 kKey wrongTweak kIv Mac.Skein512 chunk64k kCt))
  check "raw-authenticated wrong iv rejected"
    (isLeft (Engine.decryptRawAuthenticated TF256 kKey kTweak wrongIv Mac.Skein512 chunk64k kCt))
  check "raw-authenticated decrypt rejects an over-cap chunk size"
    (Engine.decryptRawAuthenticated TF256 kKey kTweak kIv Mac.Skein512 (128 * 1024 * 1024) kCt
       == Left "chunk size 134217728 exceeds the accepted maximum")

  -- Streaming (Handle-based, constant memory) must produce identical bytes to
  -- the in-memory form and round-trip, across multiple frames.
  let rawBig = seqBytes 500
      rawBytesOut =
        either (error . ("raw-authenticated stream test setup: " ++)) id
          (Engine.encryptRawAuthenticated TF256 rawKey256 rawTweak rawIv256 Mac.Skein512 64 rawBig)
      rawPtF = "/tmp/dorado-hs-raw-pt"
      rawCtF = "/tmp/dorado-hs-raw-ct"
      rawOutF = "/tmp/dorado-hs-raw-out"
  BS.writeFile rawPtF rawBig
  rEnc <- withFile rawPtF ReadMode $ \hin -> withFile rawCtF WriteMode $ \hout ->
    Engine.encryptRawAuthenticatedStream TF256 rawKey256 rawTweak rawIv256 Mac.Skein512 64 hin hout
  streamCtOut <- BS.readFile rawCtF
  check "raw-authenticated stream encrypt == in-memory encrypt" (rEnc == Right () && streamCtOut == rawBytesOut)
  rDec <- withFile rawCtF ReadMode $ \hin -> withFile rawOutF WriteMode $ \hout ->
    Engine.decryptRawAuthenticatedStream TF256 rawKey256 rawTweak rawIv256 Mac.Skein512 64 hin hout
  streamPtOut <- BS.readFile rawOutF
  check "raw-authenticated stream decrypt round-trips (multi-frame)" (rDec == Right () && streamPtOut == rawBig)

  -- Streaming tamper detection: flipping a byte of the streamed ciphertext
  -- must be rejected, not silently produce wrong plaintext.
  ctBytes <- BS.readFile rawCtF
  let tamperedStreamCt = BS.concat [BS.init ctBytes, BS.singleton (BS.last ctBytes `xor` 1)]
      rawTamperF = "/tmp/dorado-hs-raw-tampered-ct"
      rawTamperOutF = "/tmp/dorado-hs-raw-tampered-out"
  BS.writeFile rawTamperF tamperedStreamCt
  rTamperDec <- withFile rawTamperF ReadMode $ \hin -> withFile rawTamperOutF WriteMode $ \hout ->
    Engine.decryptRawAuthenticatedStream TF256 rawKey256 rawTweak rawIv256 Mac.Skein512 64 hin hout
  check "raw-authenticated stream tampered ciphertext rejected" (isLeft rTamperDec)


  n <- readIORef fails
  if n == 0
    then putStrLn "\nall passed"
    else putStrLn ("\n" ++ show n ++ " FAILED") >> exitFailure
