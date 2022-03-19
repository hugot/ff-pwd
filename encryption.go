package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"
)

func make32Byte(password string) [32]byte {
	return sha256.Sum256([]byte(password))
}

func makeHex(data []byte) string {
	return hex.EncodeToString(data)
}

// encryption code as found at
// https://tutorialedge.net/golang/go-encrypt-decrypt-aes-tutorial/
func Encrypt(password string, data []byte) (int, []byte, error) {
	key := make32Byte(password)

	// generate a new aes cipher using our 32 byte long key
	c, err := aes.NewCipher(key[:])
	// if there are any errors, handle them
	if err != nil {
		return 0, nil, err
	}

	// gcm or Galois/Counter Mode, is a mode of operation
	// for symmetric key cryptographic block ciphers
	// - https://en.wikipedia.org/wiki/Galois/Counter_Mode
	gcm, err := cipher.NewGCM(c)
	// if any error generating new GCM
	// handle them
	if err != nil {
		return 0, nil, err
	}

	// creates a new byte array the size of the nonce
	// which must be passed to Seal
	nonceSize := gcm.NonceSize()
	nonce := make([]byte, nonceSize)
	// populates our nonce with a cryptographically secure
	// random sequence
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return 0, nil, err
	}

	// here we encrypt our text using the Seal function
	// Seal encrypts and authenticates plaintext, authenticates the
	// additional data and appends the result to dst, returning the updated
	// slice. The nonce must be NonceSize() bytes long and unique for all
	// time, for a given key.
	return nonceSize, gcm.Seal(nonce, nonce, data, nil), nil
}

// Decryption code as found at
// https://tutorialedge.net/golang/go-encrypt-decrypt-aes-tutorial/
func Decrypt(password string, nonceSize int, ciphertext []byte) ([]byte, error) {
	key := make32Byte(password)

	c, err := aes.NewCipher(key[:])
	if err != nil {
		fmt.Println(err)
	}

	gcm, err := cipher.NewGCM(c)
	if err != nil {
		fmt.Println(err)
	}

	if len(ciphertext) < nonceSize {
		fmt.Println(err)
	}

	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	return gcm.Open(nil, nonce, ciphertext, nil)
}

const PasswordSaltLength int = 8

// returns password hash  and salt, in that order
func HashPassword(password string, saltPtr *[]byte) ([]byte, []byte) {
	var salt []byte
	if saltPtr == nil {
		salt = make([]byte, PasswordSaltLength)
		rand.Read(salt)
	} else {
		salt = *saltPtr
	}

	// "The draft RFC recommends[2] time=1, and memory=64*1024 is a sensible number." -
	// https://godoc.org/golang.org/x/crypto/argon2#Key
	hash := argon2.Key([]byte(password), salt, 1, 64*1024, 1, 32)

	return hash, salt
}

func ValidatePassword(password string, saltedPasswordHash []byte) (bool, error) {
	salt := saltedPasswordHash[0:PasswordSaltLength]
	passwordHash := saltedPasswordHash[PasswordSaltLength:]
	newPasswordHash, _ := HashPassword(password, &salt)

	return bytes.Compare(newPasswordHash, passwordHash) == 0, nil
}
