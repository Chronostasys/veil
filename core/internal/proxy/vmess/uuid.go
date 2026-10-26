package vmess

import (
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

// uuidLen is the number of bytes in a UUID (and in a VMess user id).
const uuidLen = 16

// parseUUID accepts the two spellings that appear in share links: the canonical
// 8-4-4-4-12 form and the bare 32 hex digits. Case does not matter.
func parseUUID(s string) ([uuidLen]byte, error) {
	var out [uuidLen]byte

	s = strings.ToLower(strings.TrimSpace(s))
	s = strings.TrimPrefix(s, "urn:uuid:")
	// Some subscription generators wrap the UUID in braces.
	s = strings.Trim(s, "{}")

	switch len(s) {
	case 36:
		if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
			return out, fmt.Errorf("vmess: malformed uuid %q", s)
		}
		s = s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]
	case 32:
	default:
		return out, fmt.Errorf("vmess: uuid %q must be 32 hex digits or canonical", s)
	}

	raw, err := hex.DecodeString(s)
	if err != nil {
		return out, fmt.Errorf("vmess: uuid %q is not hex: %w", s, err)
	}
	if len(raw) != uuidLen {
		return out, errors.New("vmess: uuid has wrong length")
	}
	copy(out[:], raw)
	return out, nil
}

// uuidString renders a UUID in canonical form (used by tests and errors).
func uuidString(id [uuidLen]byte) string {
	h := hex.EncodeToString(id[:])
	return h[:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:]
}

// cmdKey derives the 16-byte key that protects the request header:
//
//	MD5(uuid || "c48619fe-8f02-49e0-b9e9-edf763e17e21")
//
// Every VMess AEAD construction (auth id, header length, header payload) is
// keyed from this value.
func cmdKey(id [uuidLen]byte) [uuidLen]byte {
	h := md5.New()
	h.Write(id[:])
	h.Write([]byte(cmdKeyDerivationSuffix))
	var out [uuidLen]byte
	copy(out[:], h.Sum(nil))
	return out
}
