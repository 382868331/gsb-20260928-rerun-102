package auth

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
)

const DefaultPBKDF2Iterations = 210_000

func NewPasswordHash(password string, iterations int) (salt, hash []byte, err error) {
	salt = make([]byte, 16)
	if _, err = rand.Read(salt); err != nil {
		return nil, nil, err
	}
	hash, err = pbkdf2.Key(sha256.New, password, salt, iterations, sha256.Size)
	return salt, hash, err
}

func VerifyPassword(password string, salt, expected []byte, iterations int) bool {
	actual, err := pbkdf2.Key(sha256.New, password, salt, iterations, len(expected))
	if err != nil {
		return false
	}
	return subtle.ConstantTimeCompare(actual, expected) == 1
}
