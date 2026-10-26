package vmess

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"
)

// authIDSize is the length of the VMess AEAD authentication id.
const authIDSize = 16

// createAuthID builds the 16-byte authentication id that opens an AEAD request
// header:
//
//	plaintext = unixTime(8, BE) || random(4)
//	authID    = AES-128-ECB(KDF16(cmdKey, "AES Auth ID Encryption"), plaintext || crc32(plaintext))
//
// The server decrypts it with the same key, so the CRC is what lets it tell a
// wrong user from a corrupt packet.
func createAuthID(cmdKey []byte, timestamp int64, rnd io.Reader) ([16]byte, error) {
	var out [16]byte

	var plain [16]byte
	binary.BigEndian.PutUint64(plain[:8], uint64(timestamp))
	if _, err := io.ReadFull(rnd, plain[8:12]); err != nil {
		return out, fmt.Errorf("vmess: read auth id entropy: %w", err)
	}
	binary.BigEndian.PutUint32(plain[12:], crc32.ChecksumIEEE(plain[:12]))

	block, err := authIDCipher(cmdKey)
	if err != nil {
		return out, err
	}
	block.Encrypt(out[:], plain[:])
	return out, nil
}

func authIDCipher(cmdKey []byte) (cipher.Block, error) {
	block, err := aes.NewCipher(kdf16(cmdKey, saltAuthIDEncryptionKey))
	if err != nil {
		return nil, fmt.Errorf("vmess: auth id cipher: %w", err)
	}
	return block, nil
}

// decodeAuthID is the server half, used by tests and by nothing else: it
// recovers the timestamp and validates the CRC.
func decodeAuthID(cmdKey []byte, authID [16]byte) (timestamp int64, ok bool) {
	block, err := authIDCipher(cmdKey)
	if err != nil {
		return 0, false
	}
	var plain [16]byte
	block.Decrypt(plain[:], authID[:])
	if crc32.ChecksumIEEE(plain[:12]) != binary.BigEndian.Uint32(plain[12:]) {
		return 0, false
	}
	return int64(binary.BigEndian.Uint64(plain[:8])), true
}
