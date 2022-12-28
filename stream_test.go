package stream

import (
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	mrand "math/rand"

	"github.com/ericlagergren/stream/internal/golden"
)

// TODO(eric): add AD, info tests

func randKey() []byte {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		panic(err)
	}
	return key
}

// diff returns an error describing why a and b differ.
func diff(a, b []byte) error {
	if len(a) != len(b) {
		return fmt.Errorf("mismatched lengths: %d vs %d", len(a), len(b))
	}
	for i, c := range a {
		if c != b[i] {
			return fmt.Errorf("mismatch at index %d: %#x != %#x", i, c, b[i])
		}
	}
	return nil
}

func isErrOpen(err error) bool {
	return err != nil && strings.Contains(err.Error(), "message authentication failed")
}

// TestBasic is a basic round-trip sanity test.
func TestBasic(t *testing.T) {
	var (
		ciphertext bytes.Buffer
		plaintext  bytes.Buffer
		input      = io.TeeReader(rand.Reader, &plaintext)
		key        = randKey()
	)

	w, err := NewWriter(&ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })

	_, err = io.CopyN(w, input, ChunkSize*5+ChunkSize/2)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := NewReader(&ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}

	var got bytes.Buffer
	_, err = io.Copy(&got, r)
	if err != nil {
		t.Fatal(err)
	}

	if !bytes.Equal(got.Bytes(), plaintext.Bytes()) {
		t.Fatal(diff(got.Bytes(), plaintext.Bytes()))
	}
}

// TestModified tests NewReader rejects modified ciphertexts.
func TestModified(t *testing.T) {
	var (
		ciphertext bytes.Buffer
		plaintext  bytes.Buffer
		input      = io.TeeReader(rand.Reader, &plaintext)
		key        = randKey()
	)

	w, err := NewWriter(&ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })

	_, err = io.CopyN(w, input, ChunkSize*5+ChunkSize/2)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	buf := ciphertext.Bytes()
	buf = buf[headerSize:]
	buf[mrand.Intn(len(buf))]++

	r, err := NewReader(&ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}

	var got bytes.Buffer
	_, err = io.Copy(&got, r)
	if !isErrOpen(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestBadKey tests NewReader rejects incorrect keys.
func TestBadKey(t *testing.T) {
	var (
		ciphertext bytes.Buffer
		plaintext  bytes.Buffer
		input      = io.TeeReader(rand.Reader, &plaintext)
		key        = randKey()
	)

	w, err := NewWriter(&ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })

	_, err = io.CopyN(w, input, ChunkSize*5+ChunkSize/2)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	key[mrand.Intn(len(key))]++

	r, err := NewReader(&ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}

	var got bytes.Buffer
	_, err = io.Copy(&got, r)
	if !isErrOpen(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestBadNonce tests NewReader rejects ciphertexts with modified
// nonces.
func TestBadNonce(t *testing.T) {
	var (
		ciphertext bytes.Buffer
		plaintext  bytes.Buffer
		input      = io.TeeReader(rand.Reader, &plaintext)
		key        = randKey()
	)

	w, err := NewWriter(&ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })

	const (
		N = 5
	)
	_, err = io.CopyN(w, input, N*ChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	buf := ciphertext.Bytes()

	// Trim header and all but final chunk.
	buf = buf[headerSize:]
	buf = buf[len(buf)/(ChunkSize+overhead):]

	// Extract the nonce and set its counter to N+1 (i.e., the
	// would-be next chunk's nonce).
	nonce := buf[:nonceSize]
	// Store, clear, then reset the EOF byte since setNonce will
	// panic if called on a nonce where EOF is set.
	eof := nonce[eofIdx]
	nonce[eofIdx] = 0
	incrNonce(nonce)
	nonce[eofIdx] = eof

	r, err := NewReader(&ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}

	var got bytes.Buffer
	_, err = io.Copy(&got, r)
	if !isErrOpen(err) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestTruncated tests NewReader rejects truncated ciphertexts.
func TestTruncated(t *testing.T) {
	var (
		ciphertext bytes.Buffer
		plaintext  bytes.Buffer
		input      = io.TeeReader(rand.Reader, &plaintext)
		key        = randKey()
	)

	w, err := NewWriter(&ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { w.Close() })

	const (
		N = 5
	)
	_, err = io.CopyN(w, input, N*ChunkSize)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	ciphertext.Truncate(headerSize + (N-1)*(ChunkSize+overhead))

	r, err := NewReader(&ciphertext, key)
	if err != nil {
		t.Fatal(err)
	}

	var got bytes.Buffer
	_, err = io.Copy(&got, r)
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("unexpected error: %v", err)
	}
}

// TestGolden tests against known test vectors.
func TestGolden(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "golden.json.gz"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })

	gzr, err := gzip.NewReader(f)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { gzr.Close() })

	dec := json.NewDecoder(gzr)
	for i := 0; ; i++ {
		var v golden.Vector
		err := dec.Decode(&v)
		if err != nil {
			if err == io.EOF {
				break
			}
			t.Fatalf("#%d: %v", i, err)
		}
		rng, err := golden.CSPRNG(v.Seed)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		key := make([]byte, keySize)
		_, err = io.ReadFull(rng, key)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		r, err := NewReader(bytes.NewReader(v.Ciphertext), key)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		var got bytes.Buffer
		_, err = io.Copy(&got, r)
		if err != nil {
			t.Fatalf("#%d: %v", i, err)
		}
		if !bytes.Equal(got.Bytes(), v.Plaintext) {
			t.Fatalf("#%d: %v", i, diff(got.Bytes(), v.Plaintext))
		}
	}
}

func BenchmarkReader(b *testing.B) {
	var (
		ciphertext []byte
		key        = randKey()
	)
	w, err := NewWriter((*wbuf)(&ciphertext), key)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { w.Close() })

	const (
		size = 10*ChunkSize + ChunkSize/3
	)
	_, err = io.CopyN(w, rand.Reader, size)
	if err != nil {
		b.Fatal(err)
	}
	if err := w.Close(); err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.SetBytes(int64(len(ciphertext)))

	for i := 0; i < b.N; i++ {
		r, err := NewReader(bytes.NewReader(ciphertext), key)
		if err != nil {
			b.Fatal(err)
		}
		_, err = io.Copy(io.Discard, r)
		if err != nil {
			b.Fatal(err)
		}
	}
}

type wbuf []byte

var _ io.Writer = (*wbuf)(nil)

func (w *wbuf) Write(p []byte) (int, error) {
	*w = append(*w, p...)
	return len(p), nil
}
