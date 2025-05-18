package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
)

var (
	ErrInvalidAESKeySize     = errors.New("invalid AES key size")
	ErrInvalidTokenFormat    = errors.New("invalid token format, expecting base64 encoded nonce+ciphertext")
	ErrCiphertextTooShort    = errors.New("ciphertext too short, cannot extract nonce")
	ErrTokenDecryptionFailed = errors.New("token decryption failed")
)

const (
	// AES-256 requires a 32-byte key.
	aes256KeyBytes = 32
	// GCM standard nonce size.
	gcmNonceSizeBytes = 12
)

// DecryptAESGCM decrypts a base64 URL encoded token string using AES-GCM.
// The aesKeyHex is the 32-byte AES key, hex-encoded.
// The tokenB64 is expected to be a base64 URL encoded string containing: nonce (12 bytes) + ciphertext.
func DecryptAESGCM(aesKeyHex string, tokenB64 string) ([]byte, error) {
	key, err := hex.DecodeString(aesKeyHex)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AES key from hex: %w", err)
	}
	if len(key) != aes256KeyBytes {
		return nil, fmt.Errorf("%w: expected %d bytes, got %d", ErrInvalidAESKeySize, aes256KeyBytes, len(key))
	}

	encryptedToken, err := base64.URLEncoding.DecodeString(tokenB64)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidTokenFormat, err)
	}

	if len(encryptedToken) < gcmNonceSizeBytes {
		return nil, fmt.Errorf("%w: length %d, minimum %d", ErrCiphertextTooShort, len(encryptedToken), gcmNonceSizeBytes)
	}

	nonce := encryptedToken[:gcmNonceSizeBytes]
	ciphertext := encryptedToken[gcmNonceSizeBytes:]

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES cipher block: %w", err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("failed to create GCM cipher: %w", err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil) // No additional authenticated data (AAD)
	if err != nil {
		// Do not wrap this error further, as it's often a generic "cipher: message authentication failed"
		// which is a clear indicator of a bad token or key.
		return nil, ErrTokenDecryptionFailed
	}

	return plaintext, nil
}
