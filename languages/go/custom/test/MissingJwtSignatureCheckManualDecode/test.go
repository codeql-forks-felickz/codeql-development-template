package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

type Claims struct {
	Username string `json:"username"`
}

var jwtKey = []byte("my_secret_key")

func extractToken(r *http.Request) string {
	bearToken := r.Header.Get("Authorization") // $ Source
	strArr := strings.Split(bearToken, " ")
	if len(strArr) == 2 {
		return strArr[1]
	}
	return ""
}

// Reduced from a handler that trusts the claims of a hand-decoded JWT without checking the signature.
func tokenValidBad(r *http.Request) (Claims, error) {
	header := Header{}
	claims := Claims{}
	token := extractToken(r)
	if token == "" {
		return claims, nil
	}
	t := strings.Split(token, ".")

	h, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(t[0])
	if err != nil {
		return claims, err
	}
	if err := json.Unmarshal(h, &header); err != nil {
		return claims, err
	}

	c, err := base64.StdEncoding.WithPadding(base64.NoPadding).DecodeString(t[1])
	if err != nil {
		return claims, err
	}
	err = json.Unmarshal(c, &claims) // $ Alert
	return claims, err
}

func decodeSegment(seg string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(seg)
}

// The payload is decoded through a helper and parsed with a streaming decoder.
func claimsViaHelperBad(r *http.Request) (*Claims, error) {
	parts := strings.SplitN(r.Header.Get("X-Token"), ".", 3) // $ Source
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	payload, err := decodeSegment(parts[1])
	if err != nil {
		return nil, err
	}
	var claims Claims
	if err := json.NewDecoder(strings.NewReader(string(payload))).Decode(&claims); err != nil { // $ Alert
		return nil, err
	}
	return &claims, nil
}

// The payload is decoded into a caller-provided buffer.
func claimsDecodeIntoBufferBad(r *http.Request) (*Claims, error) {
	cookie, err := r.Cookie("token") // $ Source
	if err != nil {
		return nil, err
	}
	parts := strings.Split(cookie.Value, ".")
	buf := make([]byte, base64.RawURLEncoding.DecodedLen(len(parts[1])))
	n, err := base64.RawURLEncoding.Decode(buf, []byte(parts[1]))
	if err != nil {
		return nil, err
	}
	var claims Claims
	err = json.Unmarshal(buf[:n], &claims) // $ Alert
	return &claims, err
}

// Not reported: the HMAC signature (third segment) is verified before the claims are trusted.
func tokenValidGood(r *http.Request) (*Claims, error) {
	parts := strings.Split(extractToken(r), ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed token")
	}
	mac := hmac.New(sha256.New, jwtKey)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, errors.New("invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims Claims
	err = json.Unmarshal(payload, &claims)
	return &claims, err
}

func verifySignature(token string) bool {
	parts := strings.Split(token, ".")
	mac := hmac.New(sha256.New, jwtKey)
	mac.Write([]byte(parts[0] + "." + parts[1]))
	sig, _ := base64.RawURLEncoding.DecodeString(parts[2])
	return hmac.Equal(sig, mac.Sum(nil))
}

// Not reported: the signature is verified by a dedicated helper before decoding the payload.
func tokenValidViaHelperGood(r *http.Request) (*Claims, error) {
	token := extractToken(r)
	if !verifySignature(token) {
		return nil, errors.New("invalid signature")
	}
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims Claims
	err = json.Unmarshal(payload, &claims)
	return &claims, err
}

// Not reported: the token is not user-controlled (for example, a token this service issued itself).
func decodeOwnToken(token string) (*Claims, error) {
	parts := strings.Split(token, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims Claims
	err = json.Unmarshal(payload, &claims)
	return &claims, err
}

// Not reported: the value is not split into dot-separated JWT segments.
func decodeCommaSeparated(r *http.Request) (*Claims, error) {
	parts := strings.Split(r.URL.Query().Get("data"), ",")
	payload, err := base64.StdEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims Claims
	err = json.Unmarshal(payload, &claims)
	return &claims, err
}

// Not reported: the payload segment is unmarshalled without being base64-decoded.
func unmarshalRawSegment(r *http.Request) (*Claims, error) {
	parts := strings.Split(r.URL.Query().Get("data"), ".")
	var claims Claims
	err := json.Unmarshal([]byte(parts[1]), &claims)
	return &claims, err
}

func main() {
	decodeOwnToken("a.b.c")
}
