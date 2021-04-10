// Package stream implements OAE2 STREAM.
package stream

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/poly1305"
)

const (
	// ChunkSize is the size of a plaintext chunk.
	ChunkSize = 1 << 16

	overhead        = poly1305.TagSize
	keySize         = chacha20poly1305.KeySize
	saltSize        = 32
	nonceSize       = chacha20poly1305.NonceSizeX
	eofIdx          = nonceSize - 1
	ctrIdx          = nonceSize - 5
	noncePrefixSize = nonceSize - 5
	headerSize      = len(version{}) + saltSize + noncePrefixSize
)

type version [4]byte

var (
	v0 = [4]byte{0, 0, 0, 1}
)

// NewWriter creates a WriteCloser that writes ciphertext to w.
func NewWriter(w io.Writer, key []byte) (io.WriteCloser, error) {
	n, err := w.Write(v0[:])
	if n < len(v0) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 32)
	_, err = rand.Read(salt)
	if err != nil {
		return nil, err
	}
	n, err = w.Write(salt)
	if n < len(salt) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	_, err = rand.Read(nonce[:noncePrefixSize])
	if err != nil {
		return nil, err
	}
	n, err = w.Write(nonce[:noncePrefixSize])
	if n < noncePrefixSize && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(derive(key, salt))
	if err != nil {
		return nil, err
	}
	return &writer{
		w:         w,
		aead:      aead,
		nonce:     nonce,
		plaintext: make([]byte, ChunkSize),
	}, nil
}

type writer struct {
	// w is the underlying Writer where ciphertext is written.
	w io.Writer
	// aead is the in-use cipher.
	aead cipher.AEAD
	// nonce is the incrementing nonce.
	nonce []byte
	// plaintext contains ChunkSize bytes of plaintext data.
	//
	// plaintext is flushed when full or when Close is called.
	plaintext []byte
	// n is the number of bytes written to plaintext.
	n int
	// err is any error that occur while writing to the
	// underlying Writer.
	//
	// err is sticky.
	err error
}

var _ io.WriteCloser = (*writer)(nil)

func (w *writer) Write(p []byte) (int, error) {
	var nw int
	for len(p) > 0 && w.err == nil {
		// Flush before copying to avoid writing a zero-sized
		// record at EOF.
		if w.n == ChunkSize {
			w.flush(false)
		}
		n := copy(w.plaintext[w.n:], p)
		w.n += n
		nw += n
		p = p[n:]
	}
	if w.err != nil {
		return 0, w.err
	}
	return nw, nil
}

func (w *writer) Close() error {
	w.flush(true)

	err := w.err
	if err == nil {
		w.err = errors.New("writer is closed")
	}
	return nil
}

func (w *writer) flush(eof bool) {
	if w.err != nil {
		return
	}
	if eof {
		setEOF(w.nonce)
	}
	ciphertext := w.aead.Seal(nil, w.nonce, w.plaintext[:w.n], nil)
	n, err := w.w.Write(ciphertext)
	if n < len(ciphertext) && err == nil {
		err = io.ErrShortWrite
	}
	w.err = err
	w.n = 0
	if !eof {
		incrNonce(w.nonce)
	}
}

// NewReader creates a ReadCloser that reads plaintext from r.
func NewReader(r io.Reader, key []byte) (io.Reader, error) {
	var vers version
	_, err := io.ReadFull(r, vers[:])
	if err != nil {
		return nil, err
	}
	switch vers {
	case v0:
		// OK
	default:
		return nil, fmt.Errorf("invalid version: %#x", vers)
	}

	salt := make([]byte, saltSize)
	_, err = io.ReadFull(r, salt)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, nonceSize)
	_, err = io.ReadFull(r, nonce[:noncePrefixSize])
	if err != nil {
		return nil, err
	}

	aead, err := chacha20poly1305.NewX(derive(key, salt))
	if err != nil {
		return nil, err
	}
	return &reader{
		r:          r,
		aead:       aead,
		nonce:      nonce,
		ciphertext: make([]byte, ChunkSize+overhead),
	}, nil
}

type reader struct {
	// r is the underlying Reader.
	r io.Reader
	// aead is the in-use cipher.
	aead cipher.AEAD
	// nonce is the incrementing nonce.
	nonce []byte
	// plaintext contains unread decrypted data.
	//
	// Sized on the first decryption.
	plaintext []byte
	// n is the number of bytes written to plaintext.
	n int
	// ciphertext is a scratch buffer for reading data.
	//
	// Sized to ChunkSize+overhead by NewReader.
	ciphertext []byte
	// err is any error that occurs while reading or decrypting
	// data.
	//
	// EOF is manually set.
	err error
}

var _ io.Reader = (*reader)(nil)

func (r *reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}

	if r.n < len(r.plaintext) && (r.err == nil || r.err != io.EOF) {
		n := copy(p, r.plaintext[r.n:])
		r.n += n
		return n, nil
	}

	if r.err != nil {
		return 0, r.err
	}

	var eof bool // is this the terminal chunk?

	n, err := io.ReadFull(r.r, r.ciphertext)
	switch err {
	// We manually set EOF upon seeing a terminal chunk, so we'll
	// only ever receive EOF here if the ciphertext is indeed
	// truncated.
	case io.EOF:
		return 0, io.ErrUnexpectedEOF
	// Reading a partial chunk means this is either the final
	// chunk or the ciphertext was truncated. In either case,
	// this is the terminal chunk.
	case io.ErrUnexpectedEOF:
		setEOF(r.nonce)
		eof = true
	case nil:
		// OK
	default:
		return 0, err
	}

	r.plaintext, r.err = r.aead.Open(
		r.plaintext[:0], r.nonce, r.ciphertext[:n], nil)
	if err != nil && !eof {
		// If the size of the plaintext is a multiple of
		// ChunkSize then the final chunk will have err == nil,
		// and so decryption will fail. Try again with the EOF
		// byte set.
		setEOF(r.nonce)
		eof = true
		r.plaintext, r.err = r.aead.Open(
			r.plaintext[:0], r.nonce, r.ciphertext[:n], nil)
	}
	if r.err != nil {
		return 0, r.err
	}

	if eof {
		r.err = io.EOF
	} else {
		incrNonce(r.nonce)
	}

	r.n = copy(p, r.plaintext)
	return r.n, r.err
}

var (
	keyInfo = []byte("stream key")
)

// derive computes HKDF(ikm, salt) and returns a new 256-bit key.
func derive(ikm, salt []byte) []byte {
	key := make([]byte, keySize)
	r := hkdf.New(sha256.New, ikm, salt, keyInfo)
	_, err := io.ReadFull(r, key)
	if err != nil {
		panic(err)
	}
	return key
}

// incrNonce sets nonce's counter to n for n in [0, 1<<32-1].
//
// If nonce is not the correct size or the EOF byte is already
// set, incrNonce panics.
func incrNonce(nonce []byte) {
	if len(nonce) != nonceSize {
		panic("stream: invalid nonce size: " + strconv.Itoa(len(nonce)))
	}
	if nonce[eofIdx] != 0 {
		panic("stream: EOF already set")
	}
	n := binary.BigEndian.Uint32(nonce[ctrIdx:eofIdx])
	if n == math.MaxUint32 {
		panic("stream: counter out of range")
	}
	binary.BigEndian.PutUint32(nonce[ctrIdx:eofIdx], n+1)
}

// setEOF sets the EOF byte
//
// If nonce is not the correct size or the EOF byte is already
// set, incrNonce panics.
func setEOF(nonce []byte) {
	if len(nonce) != nonceSize {
		panic("stream: invalid nonce size: " + strconv.Itoa(len(nonce)))
	}
	if nonce[eofIdx] != 0 {
		panic("stream: EOF already set")
	}
	nonce[eofIdx] = 1
}
