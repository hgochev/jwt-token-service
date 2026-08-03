package token

import (
	"crypto/ecdsa"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrMissingSubject = errors.New("subject must not be empty")

type Issuer struct {
	issuerURL  string
	keyID      string
	privateKey *ecdsa.PrivateKey
	tokenTTL   time.Duration
}

type Claims struct {
	Scope string `json:"scope,omitempty"`
	jwt.RegisteredClaims
}

func NewIssuer(issuerURL string, keyID string, privateKey *ecdsa.PrivateKey, tokenTTL time.Duration) (*Issuer, error) {
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

	signedToken := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	signedToken.Header["kid"] = i.keyID
	signedToken.Header["typ"] = "JWT"

	return signedToken.SignedString(i.privateKey)
}
