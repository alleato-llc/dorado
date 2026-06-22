-- | The container's MAC menu. All three options take the 32-byte MAC key and
-- produce a 32-byte tag, so the frame layout is identical regardless of choice
-- (DRDO @mac id@: 1 = HMAC-SHA256, 2 = Skein-512, 3 = keyed BLAKE3).
module Dorado.Mac
  ( Mac (..)
  , macId
  , macFromId
  , tag
  ) where

import Data.ByteString (ByteString)
import Data.Word (Word8)

import qualified Dorado.Blake3 as Blake3
import qualified Dorado.Sha256 as Sha256
import qualified Dorado.Skein as Skein

-- | Which keyed hash authenticates each frame.
data Mac = HmacSha256 | Skein512 | Blake3Keyed
  deriving (Eq, Show)

-- | The on-disk @mac id@ byte.
macId :: Mac -> Word8
macId HmacSha256 = 1
macId Skein512 = 2
macId Blake3Keyed = 3

macFromId :: Word8 -> Either String Mac
macFromId 1 = Right HmacSha256
macFromId 2 = Right Skein512
macFromId 3 = Right Blake3Keyed
macFromId n = Left ("unknown mac id " ++ show n)

-- | The 32-byte tag of @msg@ under the 32-byte @key@.
tag :: Mac -> ByteString -> ByteString -> ByteString
tag HmacSha256 key msg = Sha256.hmacSha256 key msg
tag Skein512 key msg = Skein.mac key 32 msg
tag Blake3Keyed key msg = Blake3.keyedMac key 32 msg
