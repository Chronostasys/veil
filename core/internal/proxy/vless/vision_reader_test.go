package vless

import (
	"bytes"
	"io"
	"net"
	"testing"
)

// xrayFrame builds one Vision frame the way Xray's XtlsPadding does:
// [uuid (first frame only)][command][contentLen hi/lo][paddingLen hi/lo][content][padding]
func xrayFrame(uuid []byte, command byte, content, padding []byte) []byte {
	b := make([]byte, 0, len(uuid)+5+len(content)+len(padding))
	b = append(b, uuid...)
	b = append(b, command, byte(len(content)>>8), byte(len(content)), byte(len(padding)>>8), byte(len(padding)))
	b = append(b, content...)
	b = append(b, padding...)
	return b
}

// TestVisionReaderUnpadsDownlink pins the downlink parser against a frame
// produced by the reference layout: the first frame carries the user id, the
// content is returned and the padding is skipped.
func TestVisionReaderUnpadsDownlink(t *testing.T) {
	uuid := bytes.Repeat([]byte{0x11}, 16)
	content := []byte("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
	padding := bytes.Repeat([]byte{0x00}, 233)

	var stream []byte
	stream = append(stream, xrayFrame(uuid, 0 /* continue */, content, padding)...)
	// A second frame, no uuid, shorter padding.
	stream = append(stream, xrayFrame(nil, 0, []byte("tail"), bytes.Repeat([]byte{0}, 17))...)

	cli, srv := net.Pipe()
	go func() {
		_, _ = srv.Write(stream)
	}()

	st := newVisionState(uuid)
	w := newVisionWriter(cli, st)
	r := newVisionReader(cli, cli, nil, nil, st, w)

	got := make([]byte, len(content))
	if _, err := io.ReadFull(r, got); err != nil {
		t.Fatalf("read first frame: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("content mismatch:\n got %q\nwant %q", got, content)
	}
	tail := make([]byte, 4)
	if _, err := io.ReadFull(r, tail); err != nil {
		t.Fatalf("read second frame: %v", err)
	}
	if string(tail) != "tail" {
		t.Fatalf("second frame = %q", tail)
	}
	_ = srv.Close()
}
