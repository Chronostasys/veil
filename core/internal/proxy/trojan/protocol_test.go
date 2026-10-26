package trojan

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

// TestPasswordKey pins hex(SHA-224(password)) to values produced by an
// independent tool (openssl dgst -sha224). Trojan identifies users by this
// exact 56-byte string, so any change here breaks every server.
func TestPasswordKey(t *testing.T) {
	cases := []struct{ password, want string }{
		{"password", "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"},
		{"secret-pass-42", "8824556003dea2be0e18e4b7a850179a68229274bc642590199813bf"},
	}
	for _, tc := range cases {
		got := string(passwordKey(tc.password))
		if got != tc.want {
			t.Errorf("passwordKey(%q) = %q, want %q", tc.password, got, tc.want)
		}
		if len(got) != keyHexLen {
			t.Errorf("passwordKey(%q) length = %d, want %d", tc.password, len(got), keyHexLen)
		}
	}
}

// TestHeaderLayoutGolden spells the request header out byte by byte, without
// using the encoder's own address helper, so a refactor cannot silently shift a
// field.
func TestHeaderLayoutGolden(t *testing.T) {
	const keyHex = "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"

	want := []byte(keyHex + "\r\n")
	want = append(want, 0x01)                           // command TCP
	want = append(want, 0x03, byte(len("example.com"))) // ATYP domain, len
	want = append(want, []byte("example.com")...)       // host
	want = append(want, 0x01, 0xbb)                     // port 443, big endian
	want = append(want, '\r', '\n')                     // trailing CRLF

	got, err := buildHeader(nil, passwordKey("password"), commandTCP, "example.com", 443)
	if err != nil {
		t.Fatalf("buildHeader: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("header mismatch\n got %x\nwant %x", got, want)
	}
	if len(got) != keyHexLen+2+1+2+len("example.com")+2+2 {
		t.Fatalf("unexpected header length %d", len(got))
	}

	// UDP command is 0x03 and, per the trojan spec, carries no extra framing.
	udp, err := buildHeader(nil, passwordKey("password"), commandUDP, "1.2.3.4", 53)
	if err != nil {
		t.Fatalf("buildHeader udp: %v", err)
	}
	wantUDP := append([]byte(keyHex+"\r\n"), 0x03, 0x01, 1, 2, 3, 4, 0x00, 0x35, '\r', '\n')
	if !bytes.Equal(udp, wantUDP) {
		t.Fatalf("udp header mismatch\n got %x\nwant %x", udp, wantUDP)
	}
}

// TestAddressCodec covers the SOCKS5 address encoding used by both the request
// header and UDP frames.
func TestAddressCodec(t *testing.T) {
	cases := []struct {
		host string
		port uint16
		want []byte
	}{
		{"127.0.0.1", 80, []byte{0x01, 127, 0, 0, 1, 0x00, 0x50}},
		{"example.com", 443, append([]byte{0x03, 11}, append([]byte("example.com"), 0x01, 0xbb)...)},
		// 2001:db8::1 + port 8443: ATYP 0x04, 16 address bytes, 2 port bytes.
		{"[2001:db8::1]", 8443, []byte{
			0x04, 0x20, 0x01, 0x0d, 0xb8,
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // ten zero bytes
			0x01,       // ...::1
			0x20, 0xfb, // 8443
		}},
		{"::ffff:1.2.3.4", 1, []byte{0x01, 1, 2, 3, 4, 0x00, 0x01}},
	}
	for _, tc := range cases {
		got, err := appendAddrPort(nil, tc.host, tc.port)
		if err != nil {
			t.Fatalf("appendAddrPort(%q): %v", tc.host, err)
		}
		if tc.want != nil && !bytes.Equal(got, tc.want) {
			t.Errorf("appendAddrPort(%q) = %x, want %x", tc.host, got, tc.want)
		}
		host, port, err := readAddrPort(bytes.NewReader(got))
		if err != nil {
			t.Fatalf("readAddrPort(%q): %v", tc.host, err)
		}
		if port != tc.port {
			t.Errorf("readAddrPort(%q) port = %d, want %d", tc.host, port, tc.port)
		}
		if tc.host == "::ffff:1.2.3.4" {
			if host != "1.2.3.4" {
				t.Errorf("mapped address: got host %q, want unmapped 1.2.3.4", host)
			}
			continue
		}
		if host != trimBrackets(tc.host) {
			t.Errorf("readAddrPort(%q) host = %q", tc.host, host)
		}
	}
}

func TestReadAddrPortRejectsGarbage(t *testing.T) {
	if _, _, err := readAddrPort(bytes.NewReader([]byte{0x09, 0, 0})); err == nil {
		t.Fatal("expected error for unknown address type")
	}
	if _, _, err := readAddrPort(bytes.NewReader([]byte{0x03, 0x00})); err == nil {
		t.Fatal("expected error for empty domain")
	}
	if _, _, err := readAddrPort(bytes.NewReader([]byte{0x01, 1, 2})); err == nil {
		t.Fatal("expected error for truncated IPv4")
	}
}

// TestSplitHostPort accepts the shapes a caller may hand us.
func TestSplitHostPort(t *testing.T) {
	cases := []struct {
		in   string
		host string
		port uint16
		bad  bool
	}{
		{"example.com:443", "example.com", 443, false},
		{"[2001:db8::1]:8443", "2001:db8::1", 8443, false},
		{"1.2.3.4:0", "1.2.3.4", 0, false},
		{"example.com", "example.com", 0, false},
		{"::1", "::1", 0, false},
		{"", "", 0, false},
		{"host:notaport", "", 0, true},
	}
	for _, tc := range cases {
		host, port, err := splitHostPort(tc.in)
		if tc.bad {
			if err == nil {
				t.Errorf("splitHostPort(%q): expected error", tc.in)
			}
			continue
		}
		if err != nil {
			t.Fatalf("splitHostPort(%q): %v", tc.in, err)
		}
		if host != tc.host || port != tc.port {
			t.Errorf("splitHostPort(%q) = (%q, %d), want (%q, %d)", tc.in, host, port, tc.host, tc.port)
		}
	}
}

// TestUDPFrameLayout checks the exact frame shape a trojan server parses:
// [ATYP ADDR PORT][2-byte length][CRLF][payload].
func TestUDPFrameLayout(t *testing.T) {
	payload := []byte("hello")
	frame, err := appendAddrPort(nil, "example.com", 53)
	if err != nil {
		t.Fatalf("appendAddrPort: %v", err)
	}
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(payload)))
	frame = append(frame, '\r', '\n')
	frame = append(frame, payload...)

	want := []byte{0x03, 11}
	want = append(want, []byte("example.com")...)
	want = append(want, 0x00, 0x35, 0x00, 0x05, '\r', '\n')
	want = append(want, payload...)
	if !bytes.Equal(frame, want) {
		t.Fatalf("udp frame mismatch\n got %x\nwant %x", frame, want)
	}

	// And it round-trips through the client's own reader.
	host, port, err := readAddrPort(bytes.NewReader(frame))
	if err != nil {
		t.Fatalf("readAddrPort: %v", err)
	}
	if host != "example.com" || port != 53 {
		t.Fatalf("round trip = (%q, %d)", host, port)
	}
}

func TestToAddrPort(t *testing.T) {
	ap, err := toAddrPort("1.2.3.4", 53)
	if err != nil {
		t.Fatalf("toAddrPort: %v", err)
	}
	if ap != netip.MustParseAddrPort("1.2.3.4:53") {
		t.Fatalf("got %v", ap)
	}
	ap, err = toAddrPort("::ffff:1.2.3.4", 53)
	if err != nil {
		t.Fatalf("toAddrPort mapped: %v", err)
	}
	if ap.Addr().Is4In6() {
		t.Fatalf("expected unmapped address, got %v", ap)
	}
}
