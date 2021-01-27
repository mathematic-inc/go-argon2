package argon2

import (
	"errors"
	"fmt"
)

// ErrMismatchedHashAndPassword - The error returned from CompareHashAndPassword when a password and hash do
// not match.
var ErrMismatchedHashAndPassword = errors.New("mu-io/go-argon2: hashedPassword is not the hash of the given password")

// ErrHashTooShort - The error returned from CompareHashAndPassword when a hash is too short to
// be a argon2 hash.
var ErrHashTooShort = errors.New("mu-io/go-argon2: hashedSecret too short to be a argon2ed password")

// HashVersionNotSupportedError - The error returned from CompareHashAndPassword when a hash was created with
// a argon2 version newer than this implementation.
type HashVersionNotSupportedError uint8

func (hv HashVersionNotSupportedError) Error() string {
	return fmt.Sprintf("mu-io/go-argon2: argon2 algorithm version '%d' requested is not equal to the current version '%d'", hv, version)
}

// HashVariantNotSupportedError - The error returned from CompareHashAndPassword when a hash was created with
// a argon2 variant not supported.
type HashVariantNotSupportedError []byte

func (hv HashVariantNotSupportedError) Error() string {
	return fmt.Sprintf("mu-io/go-argon2: argon2 algorithm variant '%s' is not suppored", string(hv))
}

// InvalidHashPrefixError - The error returned from CompareHashAndPassword when a hash starts with something other than '$'
type InvalidHashPrefixError byte

func (ih InvalidHashPrefixError) Error() string {
	return fmt.Sprintf("mu-io/go-argon2: argon2 hashes must start with '$', but hashedSecret started with '%c'", byte(ih))
}
