package ss

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// SIP022 UDP framing.
//
// AES methods (the packet header is a raw AES block, no AEAD):
//
//	encrypted header (16B = session id || packet id)
//	AEAD body (nonce = last 4 bytes of session id || packet id)
//
// chacha20 methods (XChaCha20-Poly1305, 24-byte nonce in the clear):
//
//	nonce (24B) || XAEAD(session id || packet id || body)
//
// Body plaintext (client -> server):
//
//	type(1)=0 || timestamp(8) || padding length(2) || padding || addr || payload
//
// and (server -> client):
//
//	type(1)=1 || timestamp(8) || client session id(8) || padding length(2) || padding || addr || payload
const (
	sip022UDPMinLen    = 16 + aeadTagSize
	sip022UDPNonceSize = 24
	// sip022ServerSessionIdle is how long a superseded server session is still
	// accepted, so in-flight packets are not dropped on a server restart.
	sip022ServerSessionIdle = 60 * time.Second
)

type sip022ServerSession struct {
	id       uint64
	aead     cipher.AEAD
	lastSeen time.Time
}

// sip022PacketSession is the client side of one 2022 UDP association.
type sip022PacketSession struct {
	c   *Cipher
	psk []byte

	sessionID uint64
	packetID  atomic.Uint64

	headerBlock cipher.Block // AES packet header cipher
	bodyAEAD    cipher.AEAD  // AES body cipher (key derived from sessionID)
	xaead       cipher.AEAD  // chacha packet cipher

	mu       sync.Mutex
	current  *sip022ServerSession
	previous *sip022ServerSession
}

func newSIP022PacketSession(c *Cipher, psk []byte) (*sip022PacketSession, error) {
	s := &sip022PacketSession{c: c, psk: psk}
	for {
		id := randomBytes(8)
		s.sessionID = binary.BigEndian.Uint64(id)
		if s.sessionID != 0 {
			break
		}
	}
	var err error
	if c.IsChaCha {
		s.xaead, err = c.NewXAEAD(psk)
	} else {
		s.headerBlock, err = c.NewBlock(psk)
		if err != nil {
			return nil, err
		}
		sessionIDBytes := binary.BigEndian.AppendUint64(nil, s.sessionID)
		bodyKey := deriveSessionSubKey(psk, sessionIDBytes, c.KeySize)
		s.bodyAEAD, err = c.NewAEAD(bodyKey)
	}
	if err != nil {
		return nil, err
	}
	return s, nil
}

// SessionID exposes the client session id (used by tests).
func (s *sip022PacketSession) SessionID() uint64 { return s.sessionID }

func (s *sip022PacketSession) encode(dst netip.AddrPort, payload []byte) ([]byte, error) {
	packetID := s.packetID.Add(1) - 1

	// SIP022 asks clients to pad DNS queries, which are tiny and otherwise
	// trivially fingerprintable.
	paddingLen := 0
	if dst.Port() == 53 && len(payload) < sip022MaxPadding {
		paddingLen = int(randomBytes(1)[0])%sip022MaxPadding + 1
	}

	body := make([]byte, 0, 11+paddingLen+addrSize(dst)+len(payload))
	body = append(body, headerTypeClient)
	body = appendTimestamp(body)
	body = binary.BigEndian.AppendUint16(body, uint16(paddingLen))
	body = append(body, make([]byte, paddingLen)...)
	body = appendAddr(body, dst)
	body = append(body, payload...)

	if s.c.IsChaCha {
		nonce := randomBytes(sip022UDPNonceSize)
		plain := binary.BigEndian.AppendUint64(nil, s.sessionID)
		plain = binary.BigEndian.AppendUint64(plain, packetID)
		plain = append(plain, body...)
		return s.xaead.Seal(nonce, nonce, plain, nil), nil
	}

	var rawHeader [16]byte
	binary.BigEndian.PutUint64(rawHeader[:8], s.sessionID)
	binary.BigEndian.PutUint64(rawHeader[8:], packetID)
	var encHeader [16]byte
	s.headerBlock.Encrypt(encHeader[:], rawHeader[:])

	out := make([]byte, 0, 16+len(body)+aeadTagSize)
	out = append(out, encHeader[:]...)
	return s.bodyAEAD.Seal(out, rawHeader[4:16], body, nil), nil
}

func (s *sip022PacketSession) decode(packet []byte) (netip.AddrPort, []byte, error) {
	if len(packet) < sip022UDPMinLen {
		return netip.AddrPort{}, nil, fmt.Errorf("ss: short 2022 udp packet")
	}

	if s.c.IsChaCha {
		if len(packet) < sip022UDPNonceSize+aeadTagSize {
			return netip.AddrPort{}, nil, fmt.Errorf("ss: short 2022 udp packet")
		}
		plain, err := s.xaead.Open(nil, packet[:sip022UDPNonceSize], packet[sip022UDPNonceSize:], nil)
		if err != nil {
			return netip.AddrPort{}, nil, fmt.Errorf("ss: udp decrypt: %w", err)
		}
		if len(plain) < 16+11 {
			return netip.AddrPort{}, nil, fmt.Errorf("ss: short 2022 udp body")
		}
		return s.parseBody(plain[16:])
	}

	var rawHeader [16]byte
	s.headerBlock.Decrypt(rawHeader[:], packet[:16])
	serverSessionID := binary.BigEndian.Uint64(rawHeader[:8])
	aead, err := s.serverAEAD(serverSessionID)
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	body, err := aead.Open(nil, rawHeader[4:16], packet[16:], nil)
	if err != nil {
		return netip.AddrPort{}, nil, fmt.Errorf("ss: udp decrypt: %w", err)
	}
	return s.parseBody(body)
}

func (s *sip022PacketSession) parseBody(body []byte) (netip.AddrPort, []byte, error) {
	if len(body) < 1+8+8+2 {
		return netip.AddrPort{}, nil, fmt.Errorf("ss: short 2022 udp body")
	}
	if body[0] != headerTypeServer {
		return netip.AddrPort{}, nil, fmt.Errorf("ss: unexpected udp header type %d", body[0])
	}
	if err := checkTimestamp(binary.BigEndian.Uint64(body[1:9])); err != nil {
		return netip.AddrPort{}, nil, err
	}
	if clientID := binary.BigEndian.Uint64(body[9:17]); clientID != s.sessionID {
		return netip.AddrPort{}, nil, fmt.Errorf("ss: udp packet for another client session")
	}
	paddingLen := int(binary.BigEndian.Uint16(body[17:19]))
	off := 19 + paddingLen
	if len(body) < off {
		return netip.AddrPort{}, nil, fmt.Errorf("ss: short 2022 udp padding")
	}
	dst, n, err := parseAddr(body[off:])
	if err != nil {
		return netip.AddrPort{}, nil, err
	}
	return dst, body[off+n:], nil
}

// serverAEAD returns the body cipher for a server session, deriving it on first
// use. Unlike SIP022 §3.2.4 we do accept a new server session at any time (a
// restarted server cannot know its old session id); the previous session stays
// valid for a minute so packets already in flight still decrypt.
func (s *sip022PacketSession) serverAEAD(sessionID uint64) (cipher.AEAD, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	if s.current != nil && s.current.id == sessionID {
		s.current.lastSeen = now
		return s.current.aead, nil
	}
	if s.previous != nil && s.previous.id == sessionID && now.Sub(s.previous.lastSeen) < sip022ServerSessionIdle {
		s.previous.lastSeen = now
		return s.previous.aead, nil
	}
	sessionIDBytes := binary.BigEndian.AppendUint64(nil, sessionID)
	key := deriveSessionSubKey(s.psk, sessionIDBytes, s.c.KeySize)
	aead, err := s.c.NewAEAD(key)
	if err != nil {
		return nil, err
	}
	if s.previous != nil && now.Sub(s.previous.lastSeen) >= sip022ServerSessionIdle {
		s.previous = nil
	}
	if s.current != nil {
		s.previous = s.current
	}
	s.current = &sip022ServerSession{id: sessionID, aead: aead, lastSeen: now}
	return aead, nil
}
