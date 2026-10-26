package blake3

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// Vector inputs are filled with a repeating 251-byte sequence: 0,1,...,250,0,1,...
func vectorInput(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// Official test vectors from BLAKE3-team/BLAKE3 test_vectors/test_vectors.json.
var (
	vectorKey     = []byte("whats the Elvish word for friend")
	vectorContext = "BLAKE3 2019-12-27 16:29:52 test vectors context"
)

type vector struct {
	length  int
	hash    string
	keyed   string
	derived string
}

var vectors = []vector{
	{
		length:  0,
		hash:    "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
		keyed:   "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
		derived: "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d",
	},
	{
		length:  1,
		hash:    "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213",
		keyed:   "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b",
		derived: "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c",
	},
	{
		length:  1024,
		hash:    "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7",
		keyed:   "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4",
		derived: "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706",
	},
	{
		length:  1025,
		hash:    "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444",
		keyed:   "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69",
		derived: "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb",
	},
	{
		length:  2048,
		hash:    "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a",
		keyed:   "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1",
		derived: "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23",
	},
	{
		length:  2049,
		hash:    "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030",
		keyed:   "9f29700902f7c86e514ddc4df1e3049f258b2472b6dd5267f61bf13983b78dd5",
		derived: "2ea477c5515cc3dd606512ee72bb3e0e758cfae7232826f35fb98ca1bcbdf273",
	},
	{
		length:  3072,
		hash:    "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2",
		keyed:   "044a0e7b172a312dc02a4c9a818c036ffa2776368d7f528268d2e6b5df191770",
		derived: "050df97f8c2ead654d9bb3ab8c9178edcd902a32f8495949feadcc1e0480c46b",
	},
	{
		length:  3073,
		hash:    "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3",
		keyed:   "68dede9bef00ba89e43f31a6825f4cf433389fedae75c04ee9f0cf16a427c95a",
		derived: "72613c9ec9ff7e40f8f5c173784c532ad852e827dba2bf85b2ab4b76f7079081",
	},
	{
		length:  4096,
		hash:    "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969",
		keyed:   "befc660aea2f1718884cd8deb9902811d332f4fc4a38cf7c7300d597a081bfc0",
		derived: "1e0d7f3db8c414c97c6307cbda6cd27ac3b030949da8e23be1a1a924ad2f25b9",
	},
	{
		length:  4097,
		hash:    "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995",
		keyed:   "00df940cd36bb9fa7cbbc3556744e0dbc8191401afe70520ba292ee3ca80abbc",
		derived: "aca51029626b55fda7117b42a7c211f8c6e9ba4fe5b7a8ca922f34299500ead8",
	},
	{
		length:  8192,
		hash:    "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63",
		keyed:   "dc9637c8845a770b4cbf76b8daec0eebf7dc2eac11498517f08d44c8fc00d58a",
		derived: "ad01d7ae4ad059b0d33baa3c01319dcf8088094d0359e5fd45d6aeaa8b2d0c3d",
	},
}

func TestOfficialVectors(t *testing.T) {
	var key [32]byte
	copy(key[:], vectorKey)

	for _, v := range vectors {
		in := vectorInput(v.length)

		got := Sum256(in)
		if hex.EncodeToString(got[:]) != v.hash {
			t.Errorf("hash len=%d: got %x, want %s", v.length, got, v.hash)
		}

		var keyed [32]byte
		KeyedXOF(keyed[:], key, in)
		if hex.EncodeToString(keyed[:]) != v.keyed {
			t.Errorf("keyed len=%d: got %x, want %s", v.length, keyed, v.keyed)
		}

		var derived [32]byte
		DeriveKey(derived[:], vectorContext, in)
		if hex.EncodeToString(derived[:]) != v.derived {
			t.Errorf("derive len=%d: got %x, want %s", v.length, derived, v.derived)
		}
	}
}

func TestExtendedOutput(t *testing.T) {
	// The first 64 bytes of a root node are a valid 64-byte suffix extension of
	// the 32-byte output: both come from the same root node, counter 0 then 1.
	in := vectorInput(100)
	out := make([]byte, 96)
	XOF(out, in)

	sum256 := Sum256(in)
	if !bytes.Equal(out[:32], sum256[:]) {
		t.Fatalf("XOF prefix mismatch: %x vs %x", out[:32], sum256[:])
	}
	sum512 := Sum512(in)
	if !bytes.Equal(out[:64], sum512[:]) {
		t.Fatalf("Sum512 is not the 64-byte XOF prefix")
	}
	if bytes.Equal(out[:32], out[32:64]) {
		t.Fatal("XOF blocks must differ")
	}
}

func TestChunkBoundaries(t *testing.T) {
	// Inputs around the chunk boundary must not collide; this catches a broken
	// tree fold (e.g. forgetting chunk counters or start/end flags).
	seen := make(map[string]int)
	for _, n := range []int{0, 1, 63, 64, 65, 1023, 1024, 1025, 2047, 2048, 2049, 4096, 16384} {
		h := Sum256(vectorInput(n))
		if prev, ok := seen[string(h[:])]; ok {
			t.Fatalf("collision between lengths %d and %d", prev, n)
		}
		seen[string(h[:])] = n
	}
}

func TestDeriveKeyDeterministic(t *testing.T) {
	a := make([]byte, 32)
	b := make([]byte, 32)
	DeriveKey(a, "ctx-a", []byte("material"))
	DeriveKey(b, "ctx-b", []byte("material"))
	if bytes.Equal(a, b) {
		t.Fatal("context must affect derive_key output")
	}
	c := make([]byte, 32)
	DeriveKey(c, "ctx-a", []byte("material"))
	if !bytes.Equal(a, c) {
		t.Fatal("derive_key must be deterministic")
	}
}
