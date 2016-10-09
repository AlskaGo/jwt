package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	jsonVerification "github.com/AlskaGo/jwt/json"
	"github.com/AlskaGo/jwt/time"
	"strings"
)

var (
	RawURLEncoding = base64.URLEncoding.WithPadding(base64.NoPadding)
)

type JOSEHeader map[string]interface{}
type ClaimsSet map[string]string

func NewJOSEHeader() JOSEHeader {
	header := JOSEHeader{"typ": "JWT", "alg": "HS256"}

	return header
}

func (j JOSEHeader) Get(headerParameterName string) interface{} {
	headerParameterValue := j[headerParameterName]
	return headerParameterValue
}

func (j JOSEHeader) Set(joseHeader JOSEHeader) {
	for headerParameterName, headerParameterValue := range joseHeader {
		j.SetValue(headerParameterName, headerParameterValue)
	}
}

func (j JOSEHeader) SetValue(headerParameterName string, headerParameterValue interface{}) {
	j[headerParameterName] = headerParameterValue
}

func NewClaimsSet() ClaimsSet {
	claimsSet := ClaimsSet{"iat": time.UnixTimeNowToString()}

	return claimsSet
}

func (c ClaimsSet) Get(claimName string) string {
	claimValue := c[claimName]
	return claimValue
}

func (c ClaimsSet) Set(claimsSet ClaimsSet) {
	for claimName, claimValue := range claimsSet {
		c.SetValue(claimName, claimValue)
	}
}

func (c ClaimsSet) SetValue(claimName, claimValue string) {
	c[claimName] = claimValue
}

func MacComputation(joseHeader JOSEHeader, claimsSet ClaimsSet, secret string) (string, error) {
	header, err := json.Marshal(joseHeader)
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(claimsSet)
	if err != nil {
		return "", err
	}

	JWTProtectedHeader := RawURLEncoding.EncodeToString(header)
	JWTPayload := RawURLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(JWTProtectedHeader + "." + JWTPayload))
	JWSSignature := RawURLEncoding.EncodeToString(mac.Sum(nil))

	JWT := JWTProtectedHeader + "." + JWTPayload + "." + JWSSignature

	return JWT, nil
}

func MacValidation(JWT, secret string) (bool, error) {
	JWTComponents := strings.Split(JWT, ".")

	JWTProtectedHeader := JWTComponents[0]
	JWTPayload := JWTComponents[1]
	JWSSignature := JWTComponents[2]

	decodedJWTProtectedHeader, err := RawURLEncoding.DecodeString(JWTProtectedHeader)
	if err != nil {
		return false, err
	}

	header, err := json.Marshal(string(decodedJWTProtectedHeader))
	if err != nil {
		return false, err
	}

	if jsonVerification.HasDuplicatedKey(header) {
		return false, errors.New("Header Paramter name must not duplicated")
	}

	decodedPayload, err := RawURLEncoding.DecodeString(JWTPayload)
	if err != nil {
		return false, err
	}

	decodedJWTSignature, err := RawURLEncoding.DecodeString(JWSSignature)
	if err != nil {
		return false, err
	}

	var joseHeader JOSEHeader
	if err := json.Unmarshal(decodedJWTProtectedHeader, &joseHeader); err != nil {
		return false, err
	}

	var claimsSet ClaimsSet
	if err := json.Unmarshal(decodedPayload, &claimsSet); err != nil {
		return false, err
	}

	expectedJWT, err := MacComputation(joseHeader, claimsSet, secret)
	if err != nil {
		return false, err
	}

	decodedExpectedJWTSignature, err := RawURLEncoding.DecodeString(strings.Split(expectedJWT, ".")[2])

	if !hmac.Equal(decodedJWTSignature, decodedExpectedJWTSignature) {
		return false, errors.New("Invalid signature")
	}

	return true, nil
}
