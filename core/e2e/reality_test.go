package e2e

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"io"
	"net"
	"testing"
	"time"

	"github.com/xtls/reality"

	"veil/internal/config"
	"veil/internal/transport"
)

// TestRealityEcho isolates the REALITY client against the official server.
func TestRealityEcho(t *testing.T) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pbk := base64.RawURLEncoding.EncodeToString(priv.PublicKey().Bytes())

	destAddr := tlsCamouflage(t)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	cfg := &reality.Config{
		DialContext:            (&net.Dialer{}).DialContext,
		Type:                   "tcp",
		Dest:                   destAddr,
		ServerNames:            map[string]bool{"www.icloud.com": true},
		PrivateKey:             priv,
		ShortIds:               map[[8]byte]bool{{}: true},
		SessionTicketsDisabled: true,
		MaxTimeDiff:            30 * time.Second,
	}
	// The server must know the target's post-handshake record lengths before it
	// will finish a handshake (NewListener does this automatically).
	reality.DetectPostHandshakeRecordsLens(cfg)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				rc, err := reality.Server(context.Background(), c, cfg)
				if err != nil {
					t.Logf("server: %v", err)
					c.Close()
					return
				}
				buf := make([]byte, 4)
				if _, err := io.ReadFull(rc, buf); err != nil {
					t.Logf("server read: %v", err)
					return
				}
				t.Logf("server got %q", buf)
				rc.Write([]byte("pong"))
			}()
		}
	}()

	d, err := transport.Reality(transport.TCP(ln.Addr().String()), &config.TLS{
		Enabled:    true,
		ServerName: "www.icloud.com",
		Reality:    &config.Reality{PublicKey: pbk},
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	conn, err := d.Dial(ctx)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != "pong" {
		t.Fatalf("got %q", buf)
	}
}
