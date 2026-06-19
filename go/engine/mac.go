package engine

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"

	"github.com/alleato-llc/dorado/go/blake3"
	"github.com/alleato-llc/dorado/go/skein"
)

// macTag computes a 32-byte tag over signed under the selected MAC.
func macTag(mac MacID, macKey, signed []byte) []byte {
	switch mac {
	case MacSkein:
		return skein.MAC(macKey, tagLen, signed)
	case MacHMAC:
		h := hmac.New(sha256.New, macKey)
		h.Write(signed)
		return h.Sum(nil)
	case MacBLAKE3:
		var key [32]byte
		copy(key[:], macKey)
		out := make([]byte, tagLen)
		blake3.KeyedMAC(&key, out, signed)
		return out
	}
	return nil
}

// macVerify recomputes the tag and compares it in constant time.
func macVerify(mac MacID, macKey, signed, received []byte) bool {
	expected := macTag(mac, macKey, signed)
	return subtle.ConstantTimeCompare(expected, received) == 1
}
