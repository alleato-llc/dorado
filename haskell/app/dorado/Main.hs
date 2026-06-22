-- | dorado: the password/raw-key encryption CLI. Password mode derives a key with
-- a KDF and writes an authenticated, self-describing container; raw-key mode is
-- bare, unauthenticated CTR. `inspect` prints a container's non-secret header.
-- Cross-compatible with the other ports' `dorado` CLIs.
module Main (main) where

import Control.Monad (unless)
import Data.Char (digitToInt, isHexDigit, isSpace)
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Char8 as C8
import Data.ByteString (ByteString)

import qualified Dorado.Engine as E
import qualified Dorado.Kdf as Kdf
import qualified Dorado.Mac as Mac
import qualified Dorado.Threefish as TF

version :: String
version = "dorado 0.1.0"

usageText :: String
usageText =
  unlines
    [ "dorado - Threefish encryption with a password container or a raw key."
    , ""
    , "Usage:"
    , "  dorado encrypt --password-stdin --in <f> --out <f> [--kdf K --mac M --variant V"
    , "                 --chunk-kib N --label L --tweak HEX + KDF cost flags]"
    , "  dorado encrypt --key HEX|--key-file F --iv HEX [--tweak HEX] --in <f> --out <f>"
    , "  dorado decrypt --password-stdin [--expect-label L] --in <f> --out <f>"
    , "  dorado decrypt --key HEX|--key-file F --iv HEX [--tweak HEX] --in <f> --out <f>"
    , "  dorado inspect --in <f>"
    , ""
    , "  --kdf argon2id|scrypt|pbkdf2   --mac skein|hmac-sha256|blake3   --variant 256|512|1024"
    , "  cost: --argon2-mem-mib --argon2-time --argon2-par --scrypt-logn --scrypt-r --scrypt-p --pbkdf2-rounds"
    , "  -h, --help    -V, --version"
    ]

valueFlags :: [String]
valueFlags =
  [ "--key", "--key-file", "--iv", "--tweak", "--variant", "--kdf", "--mac"
  , "--chunk-kib", "--label", "--expect-label", "--in", "--out"
  , "--argon2-mem-mib", "--argon2-time", "--argon2-par"
  , "--scrypt-logn", "--scrypt-r", "--scrypt-p", "--pbkdf2-rounds"
  ]

type Flags = ([(String, String)], [String])

parseFlags :: [String] -> Either String Flags
parseFlags = go [] []
  where
    go vs bs [] = Right (reverse vs, reverse bs)
    go vs bs (a : rest)
      | a `elem` valueFlags = case rest of
          (v : rest') -> go ((a, v) : vs) bs rest'
          [] -> Left (a ++ " needs a value")
      | take 1 a == "-" = go vs (a : bs) rest
      | otherwise = Left ("unexpected argument " ++ a)

val :: Flags -> String -> Maybe String
val (vs, _) name = lookup name vs

has :: Flags -> String -> Bool
has (_, bs) name = name `elem` bs

die :: String -> IO a
die msg = hPutStrLn stderr ("dorado: " ++ msg) >> exitFailure

orDie :: Either String a -> IO a
orDie = either die pure

main :: IO ()
main = do
  args <- getArgs
  if any (`elem` ["-h", "--help"]) args
    then putStr usageText
    else if any (`elem` ["-V", "--version"]) args
      then putStrLn version
      else case args of
        ("encrypt" : rest) -> withFlags rest runEncrypt
        ("decrypt" : rest) -> withFlags rest runDecrypt
        ("inspect" : rest) -> withFlags rest runInspect
        (cmd : _) -> die ("unknown command '" ++ cmd ++ "'\n\n" ++ usageText)
        [] -> die ("missing command\n\n" ++ usageText)
  where
    withFlags rest k = either die k (parseFlags rest)

isPasswordMode :: Flags -> Bool
isPasswordMode f = has f "--password-stdin" || has f "--password"

-- ---------------------------------------------------------------------------
-- encrypt / decrypt / inspect
-- ---------------------------------------------------------------------------

runEncrypt :: Flags -> IO ()
runEncrypt f = do
  tweak <- orDie (parseTweak (val f "--tweak"))
  input <- readInput (val f "--in")
  if isPasswordMode f
    then do
      password <- readPassword
      opts <- orDie (buildOptions f)
      container <- E.encryptPassword password opts tweak input
      writeOutput (val f "--out") container
    else do
      (key, iv) <- rawKeyIv f
      out <- orDie (E.rawCtr key tweak iv input)
      writeOutput (val f "--out") out

runDecrypt :: Flags -> IO ()
runDecrypt f = do
  input <- readInput (val f "--in")
  if isPasswordMode f
    then do
      password <- readPassword
      let expect = fmap C8.pack (val f "--expect-label")
      pt <- orDie (E.decryptPasswordExpecting password expect input)
      writeOutput (val f "--out") pt
    else do
      (key, iv) <- rawKeyIv f
      tweak <- orDie (parseTweak (val f "--tweak"))
      out <- orDie (E.rawCtr key tweak iv input)
      writeOutput (val f "--out") out

runInspect :: Flags -> IO ()
runInspect f = do
  input <- readInput (val f "--in")
  info <- orDie (E.inspect input)
  putStr (formatInfo info)

-- ---------------------------------------------------------------------------
-- Options, keys, helpers
-- ---------------------------------------------------------------------------

buildOptions :: Flags -> Either String E.Options
buildOptions f = do
  variant <- case maybe "256" id (val f "--variant") of
    "256" -> Right TF.TF256
    "512" -> Right TF.TF512
    "1024" -> Right TF.TF1024
    v -> Left ("unknown variant " ++ v)
  mac <- case maybe "skein" id (val f "--mac") of
    "skein" -> Right Mac.Skein512
    "hmac-sha256" -> Right Mac.HmacSha256
    "blake3" -> Right Mac.Blake3Keyed
    m -> Left ("unknown mac " ++ m)
  kdf <- case maybe "argon2id" id (val f "--kdf") of
    "argon2id" -> Right (Kdf.Argon2id (intFlag f "--argon2-mem-mib" 64 * 1024)
                                      (intFlag f "--argon2-time" 3)
                                      (intFlag f "--argon2-par" 1))
    "scrypt" -> Right (Kdf.Scrypt (intFlag f "--scrypt-logn" 15)
                                  (intFlag f "--scrypt-r" 8)
                                  (intFlag f "--scrypt-p" 1))
    "pbkdf2" -> Right (Kdf.Pbkdf2 (intFlag f "--pbkdf2-rounds" 600000))
    k -> Left ("unknown kdf " ++ k)
  Right
    E.Options
      { E.optVariant = variant
      , E.optKdf = kdf
      , E.optMac = mac
      , E.optChunkSize = intFlag f "--chunk-kib" 64 * 1024
      , E.optLabel = maybe BS.empty C8.pack (val f "--label")
      }

intFlag :: Num a => Flags -> String -> a -> a
intFlag f name def = case val f name >>= readMaybeInt of
  Just n -> fromInteger n
  Nothing -> def

readMaybeInt :: String -> Maybe Integer
readMaybeInt s = case reads s of [(n, "")] -> Just n; _ -> Nothing

-- Resolve the raw-mode key (from --key hex or --key-file) and IV (--iv hex).
rawKeyIv :: Flags -> IO (ByteString, ByteString)
rawKeyIv f = do
  key <- case (val f "--key", val f "--key-file") of
    (Just h, _) -> orDie (parseHex h)
    (_, Just path) -> do hex <- readFile path; orDie (parseHex hex)
    _ -> die "raw-key mode needs --key or --key-file"
  iv <- case val f "--iv" of
    Just h -> orDie (parseHex h)
    Nothing -> die "raw-key mode needs --iv"
  pure (key, iv)

parseTweak :: Maybe String -> Either String ByteString
parseTweak ms = do
  t <- parseHex (maybe (replicate 32 '0') id ms)
  unless (BS.length t == 16) (Left "tweak must be 16 bytes")
  Right t

parseHex :: String -> Either String ByteString
parseHex s =
  let clean = filter (not . isSpace) s
   in if odd (length clean) || not (all isHexDigit clean)
        then Left "invalid hex"
        else Right (BS.pack (go clean))
  where
    go (a : b : rest) = fromIntegral (digitToInt a * 16 + digitToInt b) : go rest
    go _ = []

readPassword :: IO ByteString
readPassword = stripNL <$> BS.getContents
  where stripNL b = if not (BS.null b) && BS.last b == 0x0a then BS.init b else b

readInput :: Maybe FilePath -> IO ByteString
readInput Nothing = BS.getContents
readInput (Just p) = BS.readFile p

writeOutput :: Maybe FilePath -> ByteString -> IO ()
writeOutput Nothing = BS.putStr
writeOutput (Just p) = BS.writeFile p

formatInfo :: E.ContainerInfo -> String
formatInfo i =
  unlines
    [ "format:   dorado password container (DRDO v" ++ show (E.ciVersion i) ++ ")"
    , "variant:  " ++ variant
    , "kdf:      " ++ kdf
    , "mac:      " ++ mac
    , "chunk:    " ++ show (E.ciChunkSize i) ++ " bytes"
    , "salt:     " ++ show (E.ciSaltLen i) ++ " bytes"
    , "tweak:    " ++ concatMap hex2 (BS.unpack (E.ciTweak i))
    , "label:    " ++ label
    ]
  where
    hex2 b = [hexDigit (fromIntegral b `div` 16), hexDigit (fromIntegral b `mod` 16)]
    hexDigit n = "0123456789abcdef" !! n
    variant = case E.ciVariant i of TF.TF256 -> "Threefish-256"; TF.TF512 -> "Threefish-512"; TF.TF1024 -> "Threefish-1024"
    mac = case E.ciMac i of Mac.Skein512 -> "Skein-512"; Mac.HmacSha256 -> "HMAC-SHA256"; Mac.Blake3Keyed -> "BLAKE3 (keyed)"
    kdf = case E.ciKdf i of
      Kdf.Argon2id m t p -> "Argon2id (m=" ++ show m ++ " KiB, t=" ++ show t ++ ", p=" ++ show p ++ ")"
      Kdf.Scrypt logN r p -> "scrypt (log2(N)=" ++ show logN ++ ", r=" ++ show r ++ ", p=" ++ show p ++ ")"
      Kdf.Pbkdf2 rounds -> "PBKDF2-HMAC-SHA256 (rounds " ++ show rounds ++ ")"
    label = if BS.null (E.ciLabel i) then "(none)" else C8.unpack (E.ciLabel i)
