package vmess

import (
	"crypto/hmac"
	"crypto/sha256"
	"hash"
)

// Salt strings from the VMess AEAD specification. They are part of the wire
// protocol: renaming one silently breaks compatibility with every server.
const (
	saltVMessAEADKDF         = "VMess AEAD KDF"
	saltAuthIDEncryptionKey  = "AES Auth ID Encryption"
	saltAEADRespHeaderLenKey = "AEAD Resp Header Len Key"
	saltAEADRespHeaderLenIV  = "AEAD Resp Header Len IV"
	saltAEADRespHeaderKey    = "AEAD Resp Header Key"
	saltAEADRespHeaderIV     = "AEAD Resp Header IV"
	saltHeaderPayloadAEADKey = "VMess Header AEAD Key"
	saltHeaderPayloadAEADIV  = "VMess Header AEAD Nonce"
	saltHeaderPayloadLenKey  = "VMess Header AEAD Key_Length"
	saltHeaderPayloadLenIV   = "VMess Header AEAD Nonce_Length"
	cmdKeyDerivationSuffix   = "c48619fe-8f02-49e0-b9e9-edf763e17e21"
)

// kdf is VMess's chain KDF: every path element wraps the running HMAC one level
// deeper, using the previous HMAC construction as the *hash function* of the
// next level:
//
//	h_0 = HMAC-SHA256(key = "VMess AEAD KDF")
//	h_i = HMAC(key = path[i-1], hash = h_{i-1})
//	kdf = h_n(key)
//
// Xray-core implements this with a single shared HMAC instance standing in for
// both the inner and outer hash, which produces the same bytes but is rejected
// by Go 1.27 (crypto/hmac now requires the factory to return distinct values).
// Building real factories instead is both legal and semantically identical: HMAC
// resets its outer hash before folding, so the two never share live state.
func kdf(key []byte, path ...string) []byte {
	newHash := func() hash.Hash { return hmac.New(sha256.New, []byte(saltVMessAEADKDF)) }
	for _, p := range path {
		prev := newHash
		newHash = func() hash.Hash { return hmac.New(prev, []byte(p)) }
	}
	h := newHash()
	h.Write(key)
	return h.Sum(nil)
}

// kdf16 is kdf truncated to 16 bytes, the size of an AES-128 key.
func kdf16(key []byte, path ...string) []byte {
	return kdf(key, path...)[:16]
}
