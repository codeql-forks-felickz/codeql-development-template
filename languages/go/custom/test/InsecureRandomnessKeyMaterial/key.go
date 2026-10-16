package main

import (
	"crypto/aes"
	cryptorand "crypto/rand"
	"encoding/json"
	"math/rand"
	"net/http"
	"strconv"
)

type keyHolder struct {
	Value int `json:"key"`
}

type server struct {
	MessageKey keyHolder
}

// Reduced from a synthetic app: a math/rand value used as the message encryption key.
func (s *server) GetKeyV1(w http.ResponseWriter, r *http.Request) {
	if s.MessageKey.Value == 0 {
		s.MessageKey.Value = rand.Intn(100) + 1 // $ Alert
	}
	json.NewEncoder(w).Encode(map[string]string{"key": strconv.Itoa(s.MessageKey.Value)})
}

type session struct {
	SessionToken string
	Nonce        int64
}

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

func newSession() *session {
	b := make([]byte, 32)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))] // $ Source
	}
	return &session{
		SessionToken: string(b),    // $ Alert
		Nonce:        rand.Int63(), // $ Alert
	}
}

func generateApiToken() string {
	b := make([]byte, 16)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))] // $ Source
	}
	return string(b) // $ Alert
}

func deriveSecret() {
	secretKey := rand.Int63() // $ Alert
	_ = secretKey
	var hmacSalt = rand.Uint32() // $ Alert
	_ = hmacSalt
}

// Safe: crypto/rand is a cryptographically secure source.
func (s *server) GetKeyV2() {
	n, _ := cryptorand.Read(make([]byte, 1))
	s.MessageKey.Value = n
}

func generateSecureToken() string {
	b := make([]byte, 16)
	cryptorand.Read(b)
	return string(b)
}

// Safe: non-security uses of math/rand.
func pickBackoff() int {
	delay := rand.Intn(100)
	return delay
}

func shuffleKeys(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	idx := rand.Intn(len(keys))
	return keys[idx:]
}

func randomCacheKey() int {
	cacheKey := rand.Intn(10)
	return cacheKey
}

// Already reported by go/insecure-randomness (crypto sink), so not reported again here.
func encryptWithWeakKey() {
	encryptionKey := make([]byte, 16)
	for i := range encryptionKey {
		encryptionKey[i] = byte(rand.Intn(256))
	}
	aes.NewCipher(encryptionKey)
}
