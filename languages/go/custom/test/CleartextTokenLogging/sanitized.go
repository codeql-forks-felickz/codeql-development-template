package main

import (
	"crypto/sha256"
	"log"
)

func logTokenBeforeAndAfterHash(accessToken string) { // $ Source[go/clear-text-logging-token]
	log.Print(accessToken) // $ Alert[go/clear-text-logging-token]
	h := sha256.Sum256([]byte(accessToken))
	accessToken = string(h[:])
	log.Print(accessToken)
}

func logRenamedDigest(value string) {
	h := sha256.Sum256([]byte(value))
	accessToken := string(h[:])
	log.Print(accessToken)
}

func redact(value string) string {
	return "[redacted]"
}

func logRedactedToken(accessToken string) { // $ Source[go/clear-text-logging-token]
	log.Print(accessToken) // $ Alert[go/clear-text-logging-token]
	accessToken = redact(accessToken)
	log.Print(accessToken)
}
