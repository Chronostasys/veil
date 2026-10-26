// Package blake3 is a small, dependency-free implementation of the BLAKE3
// cryptographic hash function (https://github.com/BLAKE3-team/BLAKE3-specs).
//
// Only the pieces Shadowsocks 2022 needs are exposed: the plain hash, the keyed
// hash and derive_key(). All of them are one-shot APIs; BLAKE3's internal tree
// is still built exactly as specified so that inputs larger than one 1024-byte
// chunk produce the official values.
//
// The implementation is deliberately straightforward (no SIMD, no streaming
// hasher) rather than fast: it is used once per connection to derive session
// subkeys and (optionally) to build obfuscation keystreams.
package blake3

import (
	"encoding/binary"
	"math/bits"
)

const (
	blockLen = 64
	chunkLen = 1024

	flagChunkStart        = 1 << 0
	flagChunkEnd          = 1 << 1
	flagParent            = 1 << 2
	flagRoot              = 1 << 3
	flagKeyedHash         = 1 << 4
	flagDeriveKeyContext  = 1 << 5
	flagDeriveKeyMaterial = 1 << 6
)

// iv is the BLAKE2s IV, reused as BLAKE3's initial chaining value.
var iv = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

var msgPermutation = [16]uint8{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

// Sum256 returns the 32-byte BLAKE3 hash of data.
func Sum256(data []byte) [32]byte {
	var out [32]byte
	hashAll(out[:], data, iv, 0)
	return out
}

// Sum512 returns the first 64 bytes of the BLAKE3 XOF of data.
func Sum512(data []byte) [64]byte {
	var out [64]byte
	hashAll(out[:], data, iv, 0)
	return out
}

// XOF fills out with the (unkeyed) BLAKE3 extendable output of data.
func XOF(out []byte, data []byte) {
	hashAll(out, data, iv, 0)
}

// KeyedXOF fills out with the keyed BLAKE3 extendable output of data. key must
// be exactly 32 bytes.
func KeyedXOF(out []byte, key [32]byte, data []byte) {
	var k [8]uint32
	for i := 0; i < 8; i++ {
		k[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	hashAll(out, data, k, flagKeyedHash)
}

// DeriveKey implements BLAKE3's derive_key mode: a keyed KDF whose output is
// bound to context, which must be globally unique per use.
func DeriveKey(out []byte, context string, material []byte) {
	var ctxKey [32]byte
	hashAll(ctxKey[:], []byte(context), iv, flagDeriveKeyContext)

	var key [8]uint32
	for i := 0; i < 8; i++ {
		key[i] = binary.LittleEndian.Uint32(ctxKey[i*4:])
	}
	hashAll(out, material, key, flagDeriveKeyMaterial)
}

// output is a pending node of the hash tree: everything needed to squeeze its
// output (as a chaining value, or as root bytes for the final node).
type output struct {
	inputCV  [8]uint32
	block    [16]uint32
	counter  uint64
	blockLen uint32
	flags    uint32
}

func (o *output) chainingValue() [8]uint32 {
	words := compress(o.inputCV, o.block, o.counter, o.blockLen, o.flags)
	var cv [8]uint32
	copy(cv[:], words[:8])
	return cv
}

func (o *output) rootWrite(out []byte) {
	for counter := uint64(0); len(out) > 0; counter++ {
		words := compress(o.inputCV, o.block, counter, o.blockLen, o.flags|flagRoot)
		var buf [blockLen]byte
		for i := 0; i < 8; i++ {
			binary.LittleEndian.PutUint32(buf[i*4:], words[i])
		}
		n := copy(out, buf[:])
		out = out[n:]
	}
}

func g(state *[16]uint32, a, b, c, d int, mx, my uint32) {
	state[a] = state[a] + state[b] + mx
	state[d] = bits.RotateLeft32(state[d]^state[a], -16)
	state[c] = state[c] + state[d]
	state[b] = bits.RotateLeft32(state[b]^state[c], -12)
	state[a] = state[a] + state[b] + my
	state[d] = bits.RotateLeft32(state[d]^state[a], -8)
	state[c] = state[c] + state[d]
	state[b] = bits.RotateLeft32(state[b]^state[c], -7)
}

func round(state *[16]uint32, m *[16]uint32) {
	// Mix the columns.
	g(state, 0, 4, 8, 12, m[0], m[1])
	g(state, 1, 5, 9, 13, m[2], m[3])
	g(state, 2, 6, 10, 14, m[4], m[5])
	g(state, 3, 7, 11, 15, m[6], m[7])
	// Mix the diagonals.
	g(state, 0, 5, 10, 15, m[8], m[9])
	g(state, 1, 6, 11, 12, m[10], m[11])
	g(state, 2, 7, 8, 13, m[12], m[13])
	g(state, 3, 4, 9, 14, m[14], m[15])
}

func permute(m *[16]uint32) {
	var p [16]uint32
	for i := 0; i < 16; i++ {
		p[i] = m[msgPermutation[i]]
	}
	*m = p
}

// compress is the BLAKE3 compression function. It returns 16 words: the first
// eight are the chaining value, all sixteen are the XOF block.
func compress(cv [8]uint32, block [16]uint32, counter uint64, blockLen uint32, flags uint32) [16]uint32 {
	state := [16]uint32{
		cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
		iv[0], iv[1], iv[2], iv[3],
		uint32(counter), uint32(counter >> 32), blockLen, flags,
	}
	m := block
	for r := 0; r < 7; r++ {
		round(&state, &m)
		if r < 6 {
			permute(&m)
		}
	}
	for i := 0; i < 8; i++ {
		state[i] ^= state[i+8]
		state[i+8] ^= cv[i]
	}
	return state
}

func wordsFromBytes(b []byte) [16]uint32 {
	var w [16]uint32
	for i := 0; i < 16; i++ {
		w[i] = binary.LittleEndian.Uint32(b[i*4:])
	}
	return w
}

// chunkOutput hashes one chunk (1..1024 bytes) and returns the final node. When
// the encryption flags contain flagRoot the result is the root output.
func chunkOutput(chunk []byte, counter uint64, key [8]uint32, flags uint32) *output {
	blocks := (len(chunk) + blockLen - 1) / blockLen
	if blocks == 0 {
		blocks = 1
	}
	cv := key
	for i := 0; i < blocks-1; i++ {
		f := flags
		if i == 0 {
			f |= flagChunkStart
		}
		words := compress(cv, wordsFromBytes(chunk[i*blockLen:]), counter, blockLen, f)
		copy(cv[:], words[:8])
	}
	last := chunk[(blocks-1)*blockLen:]
	var block [16]uint32
	var padded [blockLen]byte
	copy(padded[:], last)
	block = wordsFromBytes(padded[:])

	f := flags | flagChunkEnd
	if blocks == 1 {
		f |= flagChunkStart
	}
	return &output{inputCV: cv, block: block, counter: counter, blockLen: uint32(len(last)), flags: f}
}

func parentOutput(left, right [8]uint32, key [8]uint32, flags uint32) *output {
	var block [16]uint32
	copy(block[:8], left[:])
	copy(block[8:], right[:])
	return &output{inputCV: key, block: block, counter: 0, blockLen: blockLen, flags: flags | flagParent}
}

// hashAll hashes data with the given key/flag setup and writes the XOF output.
func hashAll(out []byte, data []byte, key [8]uint32, flags uint32) {
	if len(data) <= chunkLen {
		// rootWrite adds flagRoot to the final compression only; intermediate
		// blocks of a multi-block chunk must not carry it.
		chunkOutput(data, 0, key, flags).rootWrite(out)
		return
	}

	nChunks := (len(data) + chunkLen - 1) / chunkLen
	var stack [][8]uint32
	total := uint64(0) // number of chunks folded so far
	for i := 0; i < nChunks-1; i++ {
		end := (i + 1) * chunkLen
		cv := chunkOutput(data[i*chunkLen:end], uint64(i), key, flags).chainingValue()
		total++
		// Merge completed subtrees: every trailing zero bit in the chunk count
		// means a subtree of that size is now complete.
		for t := total; t&1 == 0; t >>= 1 {
			left := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			cv = parentOutput(left, cv, key, flags).chainingValue()
		}
		stack = append(stack, cv)
	}

	// The last chunk stays an output node so that it can become the root.
	node := chunkOutput(data[(nChunks-1)*chunkLen:], uint64(nChunks-1), key, flags)
	for i := len(stack) - 1; i >= 0; i-- {
		node = parentOutput(stack[i], node.chainingValue(), key, flags)
	}
	node.rootWrite(out)
}
