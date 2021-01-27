// Copyright 2020 mu-io. All rights reserved.
// Use of this source code is governed by a MIT
// license that can be found in the LICENSE file.

// Package argon2 reexports golang.org/x/crypto/argon2 with their bcrypt API.
// The default parameters follow best practice.
package argon2

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"io"
	"strconv"

	"golang.org/x/crypto/argon2"
)

// Default parameters for all functions
var (
	Iterations  uint8  = 10 // See https://eprint.iacr.org/2016/759.pdf
	TimeCost    uint32 = 3
	MemoryCost  uint32 = 32 * 1024
	Threads     uint8  = 2
	MaxTagLen   uint32 = 32
	MaxSaltSize uint32 = 16
)

const version uint8 = argon2.Version

type hashed struct {
	variant     string
	version     uint8
	hash        []byte
	salt        []byte
	timeCost    uint32
	memoryCost  uint32
	parallelism uint8
}

func (h *hashed) Hash() []byte {
	v := fmt.Sprintf("v=%d", h.version)
	ps := fmt.Sprintf("m=%d,t=%d,p=%d", h.memoryCost, h.timeCost, h.parallelism)
	a := make([]byte, 5+len(h.variant)+len(v)+len(ps)+len(h.salt)+len(h.hash))
	n := copy(a[0:], "$")
	n += copy(a[n:], h.variant)
	n += copy(a[n:], "$")
	n += copy(a[n:], v)
	n += copy(a[n:], "$")
	n += copy(a[n:], ps)
	n += copy(a[n:], "$")
	n += copy(a[n:], h.salt)
	n += copy(a[n:], "$")
	n += copy(a[n:], h.hash)
	return a[:n]
}

// GenerateFromPassword returns the argon2 hash of the password.
func GenerateFromPassword(variant string, password []byte) ([]byte, error) {
	p, err := newFromPassword(variant, password)
	if err != nil {
		return nil, err
	}
	return p.Hash(), nil
}

// CompareHashAndPassword compares a argon2 hashed password with its possible
// plaintext equivalent. Returns nil on success, or an error on failure.
func CompareHashAndPassword(hashedPassword, password []byte) error {
	p, err := newFromHash(hashedPassword)
	if err != nil {
		return err
	}
	argon2, err := getVariant(p.variant)
	if err != nil {
		return err
	}
	if p.version != version {
		return HashVersionNotSupportedError(p.version)
	}
	if subtle.ConstantTimeCompare(p.Hash(), (&hashed{
		hash:        argon2(password, p.salt, p.timeCost, p.memoryCost, p.parallelism, MaxTagLen),
		variant:     p.variant,
		version:     p.version,
		timeCost:    p.timeCost,
		memoryCost:  p.memoryCost,
		parallelism: p.parallelism,
		salt:        p.salt,
	}).Hash()) != 1 {
		return ErrMismatchedHashAndPassword
	}

	return nil
}

func getVariant(name string) (func([]byte, []byte, uint32, uint32, uint8, uint32) []byte, error) {
	var alg func([]byte, []byte, uint32, uint32, uint8, uint32) []byte
	switch name {
	case "argon2id":
		alg = argon2.IDKey
	case "argon2i":
		alg = argon2.Key
	default:
		return nil, HashVariantNotSupportedError(name)
	}
	return func(a []byte, b []byte, c uint32, d uint32, e uint8, f uint32) []byte {
		hash := alg(a, b, c, d, e, f)
		var i uint8 = 1
		for ; i < Iterations; i++ {
			copy(hash, alg(hash, b, c, d, e, f))
		}
		return base64Encode(hash)
	}, nil
}

func newFromPassword(variant string, password []byte) (*hashed, error) {
	unencodedSalt := make([]byte, MaxSaltSize)
	if _, err := io.ReadFull(rand.Reader, unencodedSalt); err != nil {
		return nil, err
	}
	argon2, err := getVariant(variant)
	if err != nil {
		return nil, err
	}

	p := &hashed{
		variant:     variant,
		version:     version,
		timeCost:    TimeCost,
		memoryCost:  MemoryCost,
		parallelism: Threads,
		salt:        base64Encode(unencodedSalt),
	}
	p.hash = argon2(password, p.salt, p.timeCost, p.memoryCost, p.parallelism, MaxTagLen)
	return p, nil
}

func newFromHash(hashedSecret []byte) (*hashed, error) {
	h := bytes.SplitN(hashedSecret, []byte{'$'}, 6)
	v, _ := strconv.ParseUint(string(bytes.SplitN(h[2], []byte{'='}, 2)[1]), 10, 8)
	var (
		mem uint32
		tim uint32
		par uint8
	)
	pairs := bytes.SplitN(h[3], []byte{','}, 3)
	for _, p := range pairs {
		pair := bytes.SplitN(p, []byte{'='}, 2)
		tmp, err := strconv.ParseUint(string(pair[1]), 10, 32)
		if err != nil {
			return nil, err
		}
		switch string(pair[0]) {
		case "m":
			mem = uint32(tmp)
		case "t":
			tim = uint32(tmp)
		case "p":
			par = uint8(tmp)
		}
	}
	return &hashed{
		salt:        h[4],
		hash:        h[5],
		variant:     string(h[1]),
		version:     uint8(v),
		memoryCost:  mem,
		timeCost:    tim,
		parallelism: par,
	}, nil
}
