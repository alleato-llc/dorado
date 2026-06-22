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
  , decryptPasswordExpecting
  , ContainerInfo (..)
  , inspect
  , rawCtr
  , variantFromKeyLen
  , encryptPasswordStream
  , decryptPasswordStream
  , rawCtrStream
  , randomBytes
  ) where

import Control.Monad (unless)
import Data.Bits (shiftL, xor, (.|.))
import Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.IORef (IORef, newIORef, readIORef, writeIORef)
import Data.List (isInfixOf)
import Data.Word (Word32, Word64, Word8)
import System.IO (Handle)

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

-- | Encrypt with a caller-supplied tweak (the CLI defaults it to all zero),
-- drawing a fresh random salt and IV from the system CSPRNG.
encryptPassword :: ByteString -> Options -> ByteString -> ByteString -> IO ByteString
encryptPassword password opts tweak plaintext = do
  salt <- getRandomBytes 16
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

-- | Decrypt, optionally requiring the stored label to equal @expected@. A
-- mismatch (or no label) is rejected before any plaintext is produced.
decryptPasswordExpecting :: ByteString -> Maybe ByteString -> ByteString -> Either String ByteString
decryptPasswordExpecting password expected container = do
  (header, _) <- parseHeader container
  case expected of
    Just lbl | hLabel header /= lbl -> Left "label mismatch"
    _ -> decryptPassword password container

-- | Non-secret container parameters, as reported by 'inspect' (no password).
data ContainerInfo = ContainerInfo
  { ciVersion   :: !Word8
  , ciVariant   :: !TF.Variant
  , ciKdf       :: !Kdf.Kdf
  , ciMac       :: !Mac.Mac
  , ciChunkSize :: !Word32
  , ciSaltLen   :: !Int
  , ciTweak     :: !ByteString
  , ciLabel     :: !ByteString
  }
  deriving (Eq, Show)

-- | Read a container's header and report its non-secret parameters.
inspect :: ByteString -> Either String ContainerInfo
inspect container = do
  (h, _) <- parseHeader container
  Right
    ContainerInfo
      { ciVersion = hVersion h
      , ciVariant = hVariant h
      , ciKdf = hKdf h
      , ciMac = hMac h
      , ciChunkSize = hChunkSize h
      , ciSaltLen = BS.length (hSalt h)
      , ciTweak = hTweak h
      , ciLabel = hLabel h
      }

-- | Fresh random bytes from the system CSPRNG (for salt and IV generation).
randomBytes :: Int -> IO ByteString
randomBytes = getRandomBytes

-- | The Threefish variant for a raw key length (32/64/128 bytes).
variantFromKeyLen :: Int -> Either String TF.Variant
variantFromKeyLen 32 = Right TF.TF256
variantFromKeyLen 64 = Right TF.TF512
variantFromKeyLen 128 = Right TF.TF1024
variantFromKeyLen n = Left ("key length " ++ show n ++ " must be 32, 64, or 128 bytes")

-- | Raw-key CTR: bare, unauthenticated, headerless. Encryption and decryption are
-- the same operation. The variant is inferred from the key length; the IV must be
-- the block size, and the tweak is 16 bytes (the CLI defaults it to all zero).
rawCtr :: ByteString -> ByteString -> ByteString -> ByteString -> Either String ByteString
rawCtr key tweak iv dat = do
  variant <- variantFromKeyLen (BS.length key)
  unless (BS.length iv == TF.blockSize variant) (Left "iv must be the same length as the key")
  unless (BS.length tweak == 16) (Left "tweak must be 16 bytes")
  Right (TF.ctrApply (TF.newThreefish variant key tweak) iv dat)

-- ---------------------------------------------------------------------------
-- Streaming over Handles, in constant memory (the buffer holds at most one
-- header or one chunk). The output bytes are identical to the in-memory forms,
-- because the per-chunk CTR counter (advanced by chunk_size / block_size blocks
-- per full chunk) reproduces the one continuous CTR stream.
-- ---------------------------------------------------------------------------

-- | Advance a big-endian counter by @n@ blocks, wrapping at the IV width.
ivAdd :: ByteString -> Integer -> ByteString
ivAdd iv n =
  BS.pack [fromIntegral ((v' `div` (256 ^ (len - 1 - i))) `mod` 256) | i <- [0 .. len - 1]]
  where
    len = BS.length iv
    v' = (BS.foldl' (\acc b -> acc * 256 + toInteger b) 0 iv + n) `mod` (256 ^ len)

-- | Encrypt a password container, streaming plaintext from @hin@ to ciphertext on
-- @hout@ in constant memory. Salt, tweak, and IV are caller-provided (the CLI
-- draws random salt + IV and passes the tweak).
encryptPasswordStream :: Options -> ByteString -> ByteString -> ByteString -> ByteString -> Handle -> Handle -> IO ()
encryptPasswordStream opts salt tweak iv password hin hout = do
  BS.hPut hout headerBytes
  first <- BS.hGet hin cs
  loop 0 iv first
  where
    variant = optVariant opts
    keyLen = TF.keySize variant
    kdfOut = Kdf.derive (optKdf opts) password salt (keyLen + 32)
    encKey = BS.take keyLen kdfOut
    macKey = BS.drop keyLen kdfOut
    tf = TF.newThreefish variant encKey tweak
    cs = fromIntegral (optChunkSize opts)
    bpc = toInteger (cs `div` TF.blockSize variant)
    headerBytes =
      serializeHeader (Header 4 variant (optKdf opts) (optMac opts) (optChunkSize opts) salt tweak iv (optLabel opts))
    loop idx counter cur = do
      next <- BS.hGet hin cs
      let isLast = BS.null next
          ct = TF.ctrApply tf counter cur
          tg = Mac.tag (optMac opts) macKey (frameAad headerBytes idx isLast ct)
      BS.hPut hout (BS.concat [BS.singleton (if isLast then 1 else 0), be32 (fromIntegral (BS.length ct)), ct, tg])
      if isLast then pure () else loop (idx + 1) (ivAdd counter bpc) next

-- | Verify and decrypt a password container, streaming from @hin@ to @hout@ in
-- constant memory. Returns 'Left' on a malformed header, label mismatch,
-- authentication failure, or truncation; on failure, any plaintext already
-- written is incomplete and untrusted.
decryptPasswordStream :: ByteString -> Maybe ByteString -> Handle -> Handle -> IO (Either String ())
decryptPasswordStream password expect hin hout = do
  src <- newSrc hin
  hr <- readHeaderSrc src
  case hr of
    Left e -> pure (Left e)
    Right (header, headerBytes)
      | maybe False (/= hLabel header) expect -> pure (Left "label mismatch")
      | otherwise ->
          frames src tf macKey (hMac header) headerBytes (hChunkSize header) bpc 0 (hIv header)
      where
        variant = hVariant header
        keyLen = TF.keySize variant
        kdfOut = Kdf.derive (hKdf header) password (hSalt header) (keyLen + 32)
        encKey = BS.take keyLen kdfOut
        macKey = BS.drop keyLen kdfOut
        tf = TF.newThreefish variant encKey (hTweak header)
        bpc = toInteger (fromIntegral (hChunkSize header) `div` TF.blockSize variant)
  where
    frames src tf macKey macv headerBytes chunkSize bpc idx counter = do
      mIsLast <- srcReadExact src 1
      case mIsLast of
        Nothing -> pure (Left "truncated: no final frame before end of input")
        Just isLastB -> do
          mLen <- srcReadExact src 4
          case mLen of
            Nothing -> pure (Left "truncated frame")
            Just lenB -> do
              let ctLen = fromIntegral (decodeBE lenB) :: Int
              if ctLen > fromIntegral chunkSize
                then pure (Left "frame ct_len exceeds chunk size")
                else do
                  mCt <- srcReadExact src ctLen
                  mTag <- srcReadExact src 32
                  case (mCt, mTag) of
                    (Just ct, Just tg) -> do
                      let isLast = BS.head isLastB == 1
                          expected = Mac.tag macv macKey (frameAad headerBytes idx isLast ct)
                      if not (ctEq expected tg)
                        then pure (Left "authentication failed")
                        else if not isLast && fromIntegral (BS.length ct) /= chunkSize
                          then pure (Left "non-final frame is not a full chunk")
                          else do
                            BS.hPut hout (TF.ctrApply tf counter ct)
                            if isLast
                              then pure (Right ())
                              else frames src tf macKey macv headerBytes chunkSize bpc (idx + 1) (ivAdd counter bpc)
                    _ -> pure (Left "truncated frame")

-- | Raw-key CTR streaming (bare, unauthenticated). Encryption and decryption are
-- the same operation.
rawCtrStream :: ByteString -> ByteString -> ByteString -> Handle -> Handle -> IO (Either String ())
rawCtrStream key tweak iv hin hout =
  case variantFromKeyLen (BS.length key) of
    Left e -> pure (Left e)
    Right variant
      | BS.length iv /= TF.blockSize variant -> pure (Left "iv must be the same length as the key")
      | BS.length tweak /= 16 -> pure (Left "tweak must be 16 bytes")
      | otherwise -> Right <$> loop iv
      where
        bsize = TF.blockSize variant
        buf = 65536 - (65536 `mod` bsize)
        bpb = toInteger (buf `div` bsize)
        tf = TF.newThreefish variant key tweak
        loop counter = do
          chunk <- BS.hGet hin buf
          if BS.null chunk
            then pure ()
            else do
              BS.hPut hout (TF.ctrApply tf counter chunk)
              if BS.length chunk == buf then loop (ivAdd counter bpb) else pure ()

-- A buffered byte source over a Handle: holds leftover bytes so the header read
-- and frame reads compose without losing data.
data Src = Src !(IORef ByteString) !Handle

newSrc :: Handle -> IO Src
newSrc h = do
  ref <- newIORef BS.empty
  pure (Src ref h)

-- Read up to n bytes (fewer only at end of input).
srcRead :: Src -> Int -> IO ByteString
srcRead s@(Src ref h) n = do
  buf <- readIORef ref
  if BS.length buf >= n
    then do
      writeIORef ref (BS.drop n buf)
      pure (BS.take n buf)
    else do
      more <- BS.hGet h (max 65536 (n - BS.length buf))
      if BS.null more
        then do writeIORef ref BS.empty; pure buf
        else do writeIORef ref (buf <> more); srcRead s n

-- Read exactly n bytes, or Nothing if the input ends first.
srcReadExact :: Src -> Int -> IO (Maybe ByteString)
srcReadExact s n = do
  b <- srcRead s n
  pure (if BS.length b == n then Just b else Nothing)

-- Accumulate bytes until the header parses, leaving the frame bytes buffered.
readHeaderSrc :: Src -> IO (Either String (Header, ByteString))
readHeaderSrc (Src ref h) = go
  where
    go = do
      buf <- readIORef ref
      case parseHeader buf of
        Right (header, rest) -> do
          writeIORef ref rest
          pure (Right (header, BS.take (BS.length buf - BS.length rest) buf))
        Left e
          | "end of input" `isInfixOf` e -> do
              more <- BS.hGet h 256
              if BS.null more
                then pure (Left "truncated header")
                else do writeIORef ref (buf <> more); go
          | otherwise -> pure (Left e)

takeE :: Int -> ByteString -> Either String (ByteString, ByteString)
takeE n bs
  | BS.length bs < n = Left "truncated frame"
  | otherwise = Right (BS.splitAt n bs)

decodeBE :: ByteString -> Word32
decodeBE b = foldl' (\acc i -> acc `shiftL` 8 .|. fromIntegral (BS.index b i)) 0 [0 .. BS.length b - 1]
