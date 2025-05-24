package crypto

import (
	"crypto/sha256"
	"encoding/hex"
)

// Sha256Hex computes the SHA256 hash of an input string and returns it as a hex-encoded string.
func Sha256Hex(input string) string {
	hasher := sha256.New()
	// Write operation on hash.Hash never returns an error.
	_, _ = hasher.Write([]byte(input)) //nolint:errcheck
	return hex.EncodeToString(hasher.Sum(nil))
}
