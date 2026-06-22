-- | gyotaku: Skein-512 file hashing, a fish-print fingerprint (like sha256sum but
-- Skein). Hashes files or stdin at a selectable output length, prints BSD-tagged
-- output with --tag, and verifies checksum lists with -c/--check. Matches the
-- other ports' gyotaku CLI.
module Main (main) where

import Control.Monad (forM_, when)
import Data.Char (intToDigit, isSpace)
import Data.IORef (modifyIORef', newIORef, readIORef)
import Data.List (isPrefixOf, stripPrefix)
import System.Environment (getArgs)
import System.Exit (exitFailure)
import System.IO (hPutStrLn, stderr)
import qualified Data.ByteString as BS
import Data.ByteString (ByteString)

import qualified Dorado.Skein as Skein

version :: String
version = "gyotaku 0.1.0"

usageText :: String
usageText =
  unlines
    [ "Skein-512 file hashing, a fish-print fingerprint. Educational, unaudited."
    , ""
    , "Usage: gyotaku [OPTIONS] [FILES]..."
    , ""
    , "  --bits <BITS>  Output length in bits (a multiple of 8) [default: 256]"
    , "  -c, --check    Verify digests read from the FILES (like `sha256sum -c`)"
    , "      --tag      BSD-style tagged output: \"SKEIN-512 (file) = digest\""
    , "  -h, --help     Print help"
    , "  -V, --version  Print version"
    ]

toHex :: ByteString -> String
toHex = concatMap byte . BS.unpack
  where byte b = [intToDigit (fromIntegral b `div` 16), intToDigit (fromIntegral b `mod` 16)]

data Opts = Opts
  { oBits  :: Int
  , oCheck :: Bool
  , oTag   :: Bool
  , oFiles :: [FilePath]
  }

parse :: [String] -> Either String Opts
parse = go (Opts 256 False False [])
  where
    go o [] = Right o { oFiles = reverse (oFiles o) }
    go o ("--bits" : v : rest) = case reads v of
      [(n, "")] | n > 0 && n `mod` 8 == 0 -> go o { oBits = n } rest
      _ -> Left ("invalid --bits value " ++ v)
    go o (a : rest)
      | a == "-c" || a == "--check" = go o { oCheck = True } rest
      | a == "--tag" = go o { oTag = True } rest
      | "--" `isPrefixOf` a = Left ("unknown option " ++ a)
      | otherwise = go o { oFiles = a : oFiles o } rest

main :: IO ()
main = do
  args <- getArgs
  if any (`elem` ["-h", "--help"]) args
    then putStr usageText
    else if any (`elem` ["-V", "--version"]) args
      then putStrLn version
      else case parse args of
        Left e -> hPutStrLn stderr ("gyotaku: " ++ e) >> exitFailure
        Right o
          | oCheck o -> runCheck o
          | otherwise -> runHash o

-- Hash each file (or stdin if none) and print the digest.
runHash :: Opts -> IO ()
runHash o
  | null (oFiles o) = do
      input <- BS.getContents
      putStrLn (toHex (Skein.hash (oBits o `div` 8) input))
  | otherwise = forM_ (oFiles o) $ \f -> do
      input <- BS.readFile f
      let d = toHex (Skein.hash (oBits o `div` 8) input)
      putStrLn $
        if oTag o
          then "SKEIN-512 (" ++ f ++ ") = " ++ d
          else d ++ "  " ++ f

-- Verify checksum lists (default or tagged lines), printing "<file>: OK/FAILED".
runCheck :: Opts -> IO ()
runCheck o = do
  bad <- newIORef (0 :: Int)
  forM_ (oFiles o) $ \listFile -> do
    contents <- readFile listFile
    forM_ (lines contents) $ \line ->
      case parseCheckLine line of
        Nothing -> pure ()
        Just (expected, file) -> do
          input <- BS.readFile file
          let actual = toHex (Skein.hash (length expected `div` 2) input)
          if actual == expected
            then putStrLn (file ++ ": OK")
            else putStrLn (file ++ ": FAILED") >> modifyIORef' bad (+ 1)
  n <- readIORef bad
  when (n > 0) exitFailure

-- A "digest  file" line or a "SKEIN-512 (file) = digest" tagged line.
parseCheckLine :: String -> Maybe (String, FilePath)
parseCheckLine line
  | null trimmed = Nothing
  | Just rest <- stripPrefix "SKEIN-512 (" trimmed =
      let (file, after) = break (== ')') rest
       in case stripPrefix ") = " after of
            Just digest -> Just (digest, file)
            Nothing -> Nothing
  | otherwise =
      case break isSpace trimmed of
        (digest, sp : file) | not (null digest) -> Just (digest, dropWhile isSpace (sp : file))
        _ -> Nothing
  where trimmed = dropWhile isSpace line
