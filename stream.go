// Package stream implements OAE2 STREAM.
//
// OAE stands for Online Authenticated Encryption. Here, the term
// "online" means plaintext and ciphertext can be encrypted and
// decrypted, respectively, with one left-to-right pass [stream].
// In other words, it supports streaming.
//
// OAE2 is a simple construction: the plaintext is broken into
// chunks and each chunk is encrypted separately. A counter nonce
// is used to ensure unique nonces and to provider ordering.
//
// This package implements STREAM using XChaCha20-Poly1305. Each
// plaintext chunk_n in {0, 1, ..., N-2} is exactly 64 KiB with
// the final plaintext chunk_{N-1} being an arbitrary size less
// than or equal to 64 KiB. In other words, every chunk is the
// same size, except the final chunk may be a smaller.
//
// Borrowing from Hoang and Shen [tink], this package adds
// a random prefix to the nonces, increasing the concrete
// security bound. More specifically:
//
//    prefix counter eof
//      152    32     8  bits
//
// The EOF byte signals the end of the stream. Without an
// explicit EOF signal the stream could be susceptible to
// truncation attacks.
//
// As always, it is not a good idea to act on a plaintext until
// the entire message has been verified.
//
// References:
//
//    [stream]: https://eprint.iacr.org/2015/189.pdf
//    [tink]: https://eprint.iacr.org/2020/1019.pdf
//    [hkdf]: https://tools.ietf.org/html/rfc5869
//
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
)

const (
	// ChunkSize is the size of a plaintext chunk.
	ChunkSize = 1 << 16

	keySize  = 32
	saltSize = 32
)

// version identifies the encryption scheme used.
//
// TODO(eric): get rid of this, I'm not sure I like it.
type version [4]byte

var (
	v0 = [4]byte{0, 0, 0, 1}
)

type option struct {
	// rand supplies randomness to NewWriter.
	rand io.Reader
	// aditionalData is the AD passed to each encryption.
	additionalData []byte
	// info is the HKDF 'info' parameter.
	info []byte
	// aead returns the AEAD uses.
	aead func([]byte) (cipher.AEAD, error)
}

// Option configures NewReader and NewWriter.
type Option func(*option)

// WithAdditionalData sets additional authenticated data used in
// each encryption.
//
// Additional data is typically used to bind the ciphertext to
// a particular contect.
//
// By default, no additional data is used.
func WithAdditionalData(data []byte) Option {
	return func(o *option) {
		o.additionalData = data
	}
}

// WithInfo sets the HKDF 'info' parameter used when deriving the
// encryption key.
//
// The info parameter is typically used to bind the key to
// a particular context [hkdf].
//
// By default, the info parameter is not used.
func WithInfo(info []byte) Option {
	return func(o *option) {
		o.info = info
	}
}

// WithRand sets the Reader that supplies randomness to
// NewWriter.
//
// By default, rand.Reader is used.
func WithRand(r io.Reader) Option {
	return func(o *option) {
		o.rand = r
	}
}

// WithAEAD specifies the AEAD function, which must accept
// a 32-byte key.
//
// By default, XChaCha-Poly1305 is used.
func WithAEAD(fn func([]byte) (cipher.AEAD, error)) Option {
	return func(o *option) {
		o.aead = fn
	}
}

// NewWriter creates a WriteCloser that writes ciphertext to w.
//
// NewWriter derives the actual encryption key with HKDF.
//
// In general, it is unsafe to reuse a key.
func NewWriter(w io.Writer, key []byte, opts ...Option) (io.WriteCloser, error) {
	o := option{
		rand: rand.Reader,
	}
	for _, fn := range opts {
		fn(&o)
	}
	if o.aead == nil {
		o.aead = chacha20poly1305.NewX
	}

	n, err := w.Write(v0[:])
	if n < len(v0) && err == nil {
		err = io.ErrShortWrite
	}
	if err != nil {
		return nil, err
	}

	salt := make([]byte, 32)
	_, err = io.ReadFull(o.rand, salt)
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

	aead, err := o.aead(derive(key, salt, o.info))
	if err != nil {
		return nil, err
	}
	noncePrefixSize := aead.NonceSize() - 5

	nonce := make([]byte, aead.NonceSize())
	_, err = io.ReadFull(o.rand, nonce[:noncePrefixSize])
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
	return &writer{
		w:              w,
		aead:           aead,
		additionalData: o.additionalData,
		nonce:          nonce,
		plaintext:      make([]byte, ChunkSize),
	}, nil
}

type writer struct {
	// w is the underlying Writer where ciphertext is written.
	w io.Writer
	// aead is the in-use cipher.
	aead cipher.AEAD
	// aditionalData is the AD passed to each encryption.
	additionalData []byte
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
		setEOF(w.aead, w.nonce)
	}
	ciphertext := w.aead.Seal(
		nil, w.nonce, w.plaintext[:w.n], w.additionalData)
	n, err := w.w.Write(ciphertext)
	if n < len(ciphertext) && err == nil {
		err = io.ErrShortWrite
	}
	w.err = err
	w.n = 0
	if !eof {
		incrNonce(w.aead, w.nonce)
	}
}

// NewReader creates a ReadCloser that reads plaintext from r.
func NewReader(r io.Reader, key []byte, opts ...Option) (io.Reader, error) {
	o := option{}
	for _, fn := range opts {
		fn(&o)
	}
	if o.aead == nil {
		o.aead = chacha20poly1305.NewX
	}

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

	aead, err := o.aead(derive(key, salt, o.info))
	if err != nil {
		return nil, err
	}
	noncePrefixSize := aead.NonceSize() - 5

	nonce := make([]byte, aead.NonceSize())
	_, err = io.ReadFull(r, nonce[:noncePrefixSize])
	if err != nil {
		return nil, err
	}
	return &reader{
		r:              r,
		aead:           aead,
		additionalData: o.additionalData,
		nonce:          nonce,
		ciphertext:     make([]byte, ChunkSize+aead.Overhead()),
	}, nil
}

type reader struct {
	// r is the underlying Reader.
	r io.Reader
	// aead is the in-use cipher.
	aead cipher.AEAD
	// aditionalData is the AD passed to each encryption.
	additionalData []byte
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
	// Sized to ChunkSize+aead.Overhead by NewReader.
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

	if r.n < len(r.plaintext) && (r.err == nil || r.err == io.EOF) {
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
		setEOF(r.aead, r.nonce)
		eof = true
	case nil:
		// OK
	default:
		return 0, err
	}

	r.plaintext, r.err = r.aead.Open(
		r.plaintext[:0], r.nonce, r.ciphertext[:n], r.additionalData)
	if err != nil && !eof {
		// If the size of the plaintext is a multiple of
		// ChunkSize then the final chunk will have err == nil,
		// and so decryption will fail. Try again with the EOF
		// byte set.
		setEOF(r.aead, r.nonce)
		eof = true
		r.plaintext, r.err = r.aead.Open(
			r.plaintext[:0], r.nonce, r.ciphertext[:n], r.additionalData)
	}
	if r.err != nil {
		return 0, r.err
	}

	if eof {
		r.err = io.EOF
	} else {
		incrNonce(r.aead, r.nonce)
	}

	r.n = copy(p, r.plaintext)
	return r.n, nil
}

// derive computes HKDF(ikm, salt) and returns a new 256-bit key.
func derive(ikm, salt, info []byte) []byte {
	key := make([]byte, keySize)
	r := hkdf.New(sha256.New, ikm, salt, info)
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
func incrNonce(a cipher.AEAD, nonce []byte) {
	if len(nonce) != a.NonceSize() {
		panic("stream: invalid nonce size: " + strconv.Itoa(len(nonce)))
	}
	eofIdx := a.NonceSize() - 1
	if nonce[eofIdx] != 0 {
		panic("stream: EOF already set")
	}
	ctrIdx := a.NonceSize() - 5
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
func setEOF(a cipher.AEAD, nonce []byte) {
	if len(nonce) != a.NonceSize() {
		panic("stream: invalid nonce size: " + strconv.Itoa(len(nonce)))
	}
	eofIdx := a.NonceSize() - 1
	if nonce[eofIdx] != 0 {
		panic("stream: EOF already set")
	}
	nonce[eofIdx] = 1
}
