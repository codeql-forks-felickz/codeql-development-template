package main

import (
	"crypto/sha256"
	"log"
	"time"

	jwtv3 "github.com/dgrijalva/jwt-go/v4"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/sirupsen/logrus"
)

type Claims struct {
	Username string
	jwtv3.StandardClaims
}

type Session struct {
	User         string
	RefreshToken string
	TokenType    string
}

// Unsigned ("none" algorithm) token generated at startup, mirroring the reported finding.
func CreateFakeToken() (string, error) {
	claims := &Claims{
		Username: "someone",
		StandardClaims: jwtv3.StandardClaims{
			ExpiresAt: time.Now().Add(5 * time.Minute).Unix(),
		},
	}
	token := jwtv3.NewWithClaims(jwtv3.SigningMethodNone, claims)
	tokenString, err := token.SignedString(jwtv3.UnsafeAllowNoneSignatureType)
	if err != nil {
		log.Fatal(err)
	}
	return tokenString, nil
}

func issue(key []byte) string {
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{"sub": "someone"})
	signed, _ := tok.SignedString(key) // $ Source[go/clear-text-logging-token]
	logrus.Infof("issued %s", signed) // $ Alert[go/clear-text-logging-token]
	return signed
}

// The callee name gives no hint, so the token is recognized from the JWT signing call.
func mint(key []byte) (string, error) {
	t := jwtv3.NewWithClaims(jwtv3.SigningMethodHS256, &Claims{Username: "someone"})
	return t.SignedString(key) // $ Source[go/clear-text-logging-token]
}

func handleAccessToken(accessToken string) { // $ Source[go/clear-text-logging-token]
	log.Println("received access token:", accessToken) // $ Alert[go/clear-text-logging-token]
}

func handleSession(s Session) {
	log.Printf("refresh token for %s: %s", s.User, s.RefreshToken) // $ Alert[go/clear-text-logging-token]
}

// Negative cases.

func handleSafe(s Session, csrfToken string, accessToken string, password string) { // $ Source[go/clear-text-logging]
	// non-credential token metadata
	log.Printf("token type %s", s.TokenType)
	// CSRF tokens are not authentication credentials
	log.Printf("csrf %s", csrfToken)
	// length and digest of a token do not disclose it
	log.Printf("token length %d", len(accessToken))
	log.Printf("token digest %x", sha256.Sum256([]byte(accessToken)))
	tokenValid := accessToken != ""
	log.Printf("token valid %v", tokenValid)
	tokenCount := 3
	log.Printf("token count %d", tokenCount)
	// passwords are already reported by the standard go/clear-text-logging query
	log.Printf("password %s", password) // $ Alert[go/clear-text-logging]
}

func main() {
	fakeUser, _ := CreateFakeToken() // $ Source[go/clear-text-logging-token]
	log.Printf("Fake Token %s", fakeUser) // $ Alert[go/clear-text-logging-token]

	issue([]byte("k"))
	minted, _ := mint([]byte("k"))
	log.Print(minted) // $ Alert[go/clear-text-logging-token]
	handleAccessToken("t")
	handleSession(Session{})
	handleSafe(Session{}, "c", "a", "p")
}
