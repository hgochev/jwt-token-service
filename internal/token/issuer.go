package token

import (
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"math/big"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrMissingSubject = errors.New("subject must not be empty")

type Issuer struct {
	issuerURL  string
	keyID      string
	privateKey *rsa.PrivateKey
	tokenTTL   time.Duration
}

type Claims struct {
	Scope string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

func NewIssuer(issuerURL string, keyID string, privateKey *rsa.PrivateKey, tokenTTL time.Duration) (*Issuer, error) {
	if issuerURL == "" {
		return nil, errors.New("issuer URL should not be empty")
	}

	if keyID == "" {
		return nil, errors.New("key ID must not be empty")
	}

	if privateKey == nil {
		return nil, errors.New("private key must not be nil")
	}

	if tokenTTL <= 0 {
		return nil, errors.New("token TTL must be positive")
	}

	return &Issuer{
		issuerURL:  issuerURL,
		keyID:      keyID,
		privateKey: privateKey,
		tokenTTL:   tokenTTL,
	}, nil
}

func (i *Issuer) Issue(subject string, audience string, scope string) (string, error) {
	if subject == "" {
		return "", ErrMissingSubject
	}

	if audience == "" {
		return "", errors.New("audience must notbe empty")
	}

	now := time.Now().UTC()

	claims := Claims{
		Scope: scope,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.issuerURL,
			Subject:   subject,
			Audience:  jwt.ClaimStrings{audience},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(i.tokenTTL)),
		},
	}

	signedToken := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)

	signedToken.Header["kid"] = i.keyID
	signedToken.Header["typ"] = "JWT"

	return signedToken.SignedString(i.privateKey)
}

// JWK is a single JSON Web Key for an RSA public key (RFC 7517).
type JWK struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// JWKS is a JSON Web Key Set.
type JWKS struct {
	Keys []JWK `json:"keys"`
}

// JWKS returns the public key set for this issuer, suitable for serving at
// /.well-known/jwks.json.
func (i *Issuer) JWKS() JWKS {
	pub := &i.privateKey.PublicKey
	return JWKS{
		Keys: []JWK{
			{
				Kty: "RSA",
				Use: "sig",
				Kid: i.keyID,
				Alg: "RS256",
				N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
				E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
			},
		},
	}
}
