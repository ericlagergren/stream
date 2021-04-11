// +build ignore

package main

import (
	"archive/zip"
	"compress/gzip"
	"crypto/rand"
	"encoding/gob"
	"io"
	"os"

	"github.com/ericlagergren/stream/internal/golden"
)

func main() {
	if err := main1(); err != nil {
		panic(err)
	}
}

func main1() error {
	in, err := os.Open("poems.zip")
	if err != nil {
		return err
	}
	defer in.Close()

	stat, err := in.Stat()
	if err != nil {
		return err
	}

	r, err := zip.NewReader(in, stat.Size())
	if err != nil {
		return err
	}

	out, err := os.Create("golden.gob.gz")
	if err != nil {
		return err
	}
	defer out.Close()

	gzw, err := gzip.NewWriterLevel(out, gzip.BestCompression)
	if err != nil {
		return err
	}
	defer gzw.Close()

	enc := gob.NewEncoder(gzw)

	for _, f := range r.File {
		seed := make([]byte, 32)
		_, err := rand.Read(seed)
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			return err
		}

		buf, err := io.ReadAll(rc)
		if err != nil {
			rc.Close()
			return err
		}
		if err := rc.Close(); err != nil {
			return err
		}

		vec, err := golden.NewVector(seed, buf)
		if err != nil {
			return err
		}
		err = enc.Encode(vec)
		if err != nil {
			return err
		}
	}
	if err := gzw.Close(); err != nil {
		return err
	}
	return out.Close()
}
