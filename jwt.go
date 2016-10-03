package jwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"strconv"
	"time"
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
	claimsSet := ClaimsSet{"iat": UnixTimeNowString()}

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

func Sign(joseHeader JOSEHeader, claimsSet ClaimsSet, secret string) (string, error) {
	header, err := json.Marshal(joseHeader)
	if err != nil {
		return "", err
	}

	payload, err := json.Marshal(claimsSet)
	if err != nil {
		return "", err
	}

	RawURLEncoding := base64.URLEncoding.WithPadding(base64.NoPadding)
	base64EncodedHeader := RawURLEncoding.EncodeToString(header)
	base64EncodedPayload := RawURLEncoding.EncodeToString(payload)

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(base64EncodedHeader + "." + base64EncodedPayload))
	base64JWSSignature := RawURLEncoding.EncodeToString(mac.Sum(nil))

	JWT := base64EncodedHeader + "." + base64EncodedPayload + "." + base64JWSSignature

	return JWT, nil
}

func UnixTimeNowString() string {
	return strconv.FormatInt(time.Now().Unix(), 10)
}
