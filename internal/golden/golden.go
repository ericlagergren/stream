// Package golden implements test vectors for OAE2 STREAM.
package golden

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/gob"
	"io"
	"math"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
)

func init() {
	gob.Register(Vector{})
}

// TODO(eric): add AD, info

// Vector is a test vector.
type Vector struct {
	// Seed is the seed for the AES-CTR-based CSPRNG used to
	// generate the salt and nonce prefix.
	Seed []byte
	// Plaintext is the input.
	Plaintext []byte
	// Ciphertext is the output.
	Ciphertext []byte
}

// CSPRNG returns an AES-CTR based CSPRNG.
func CSPRNG(seed []byte) (io.Reader, error) {
	block, err := aes.NewCipher(seed)
	if err != nil {
		return nil, err
	}
	return &cipher.StreamReader{
		S: cipher.NewCTR(block, make([]byte, aes.BlockSize)),
		R: zeroReader{},
	}, nil
}

// NewVector creates a test vector with the provided plaintext.
func NewVector(seed, plaintext []byte) (Vector, error) {
	rng, err := CSPRNG(seed)
	if err != nil {
		return Vector{}, err
	}

	key := make([]byte, keySize)
	_, err = io.ReadFull(rng, key)
	if err != nil {
		return Vector{}, err
	}

	var ciphertext []byte
	ciphertext = append(ciphertext, 0, 0, 0, 1)

	salt := make([]byte, saltSize)
	_, err = io.ReadFull(rng, salt)
	if err != nil {
		return Vector{}, err
	}
	ciphertext = append(ciphertext, salt...)

	prefix := make([]byte, noncePrefixSize)
	_, err = io.ReadFull(rng, prefix)
	if err != nil {
		return Vector{}, err
	}
	ciphertext = append(ciphertext, prefix...)

	aead, err := chacha20poly1305.NewX(derive(key, salt))
	if err != nil {
		return Vector{}, err
	}

	input := plaintext
	for i := 0; ; i++ {
		n := chunkSize
		if len(input) < chunkSize {
			n = len(input)
		}
		chunk := input[:n]
		input = input[n:]

		var eof byte
		if n != chunkSize {
			eof = 1
		}

		var nonce []byte
		nonce = append(nonce, prefix...)
		nonce = append(nonce, be32(i)...)
		nonce = append(nonce, eof)
		assert(len(nonce) == nonceSize, "bad nonce size")

		ciphertext = aead.Seal(ciphertext, nonce, chunk, nil)

		if eof != 0 {
			assert(len(input) == 0, "bad input length at EOF")
			break
		}
	}

	return Vector{
		Seed:       seed,
		Plaintext:  plaintext,
		Ciphertext: ciphertext,
	}, nil
}

const (
	chunkSize       = 1 << 16
	keySize         = 32
	saltSize        = 32
	nonceSize       = 24
	noncePrefixSize = 19
)

// derive computes HKDF(ikm, salt) and returns a new 256-bit key.
func derive(ikm, salt []byte) []byte {
	key := make([]byte, keySize)
	r := hkdf.New(sha256.New, ikm, salt, nil)
	_, err := io.ReadFull(r, key)
	if err != nil {
		panic(err)
	}
	return key
}

func be32(i int) []byte {
	if i < 0 || i > math.MaxUint32 {
		panic("out of range")
	}
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(i))
	return buf
}

type zeroReader struct{}

var _ io.Reader = zeroReader{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

func assert(cond bool, msg string) {
	if !cond {
		panic(msg)
	}
}
