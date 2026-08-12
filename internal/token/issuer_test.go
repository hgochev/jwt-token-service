package token_test

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/hgochev/jwt-token-service/internal/token"
)

func newTestKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate test key: %v", err)
	}
	return key
}

func newTestIssuer(t *testing.T) *token.Issuer {
	t.Helper()
	issuer, err := token.NewIssuer("https://issuer.test", "test-key-1", newTestKey(t), 5*time.Minute)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return issuer
}

func TestNewIssuer_Valid(t *testing.T) {
	_, err := token.NewIssuer("https://issuer.test", "kid", newTestKey(t), time.Minute)
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
}

func TestNewIssuer_EmptyIssuerURL(t *testing.T) {
	_, err := token.NewIssuer("", "kid", newTestKey(t), time.Minute)
	if err == nil {
		t.Error("expected error for empty issuer URL")
	}
}

func TestNewIssuer_EmptyKeyID(t *testing.T) {
	_, err := token.NewIssuer("https://issuer.test", "", newTestKey(t), time.Minute)
	if err == nil {
		t.Error("expected error for empty key ID")
	}
}

func TestNewIssuer_NilPrivateKey(t *testing.T) {
	_, err := token.NewIssuer("https://issuer.test", "kid", nil, time.Minute)
	if err == nil {
		t.Error("expected error for nil private key")
	}
}

func TestNewIssuer_ZeroTTL(t *testing.T) {
	_, err := token.NewIssuer("https://issuer.test", "kid", newTestKey(t), 0)
	if err == nil {
		t.Error("expected error for zero TTL")
	}
}

func TestIssue_EmptySubject(t *testing.T) {
	issuer := newTestIssuer(t)
	_, err := issuer.Issue("", "audience", "")
	if err == nil {
		t.Error("expected error for empty subject")
	}
}

func TestIssue_EmptyAudience(t *testing.T) {
	issuer := newTestIssuer(t)
	_, err := issuer.Issue("sub", "", "")
	if err == nil {
		t.Error("expected error for empty audience")
	}
}

func TestIssue_ClaimsAreCorrect(t *testing.T) {
	key := newTestKey(t)
	issuer, _ := token.NewIssuer("https://issuer.test", "test-key-1", key, 5*time.Minute)

	tokenStr, err := issuer.Issue("my-subject", "my-audience", "read write")
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	parsed, err := jwt.ParseWithClaims(tokenStr, &token.Claims{}, func(t *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("parse token: %v", err)
	}

	claims, ok := parsed.Claims.(*token.Claims)
	if !ok || !parsed.Valid {
		t.Fatal("invalid token claims")
	}

	if claims.Issuer != "https://issuer.test" {
		t.Errorf("issuer: got %q, want %q", claims.Issuer, "https://issuer.test")
	}
	if claims.Subject != "my-subject" {
		t.Errorf("subject: got %q, want %q", claims.Subject, "my-subject")
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != "my-audience" {
		t.Errorf("audience: got %v, want [my-audience]", claims.Audience)
	}
	if claims.Scope != "read write" {
		t.Errorf("scope: got %q, want %q", claims.Scope, "read write")
	}
	if parsed.Header["kid"] != "test-key-1" {
		t.Errorf("kid header: got %v, want test-key-1", parsed.Header["kid"])
	}
}

func TestIssue_TokenExpiry(t *testing.T) {
	key := newTestKey(t)
	ttl := 10 * time.Minute
	issuer, _ := token.NewIssuer("https://issuer.test", "kid", key, ttl)

	before := time.Now()
	tokenStr, _ := issuer.Issue("sub", "aud", "")
	after := time.Now()

	parsed, _ := jwt.ParseWithClaims(tokenStr, &token.Claims{}, func(t *jwt.Token) (interface{}, error) {
		return &key.PublicKey, nil
	})
	claims := parsed.Claims.(*token.Claims)

	expiry := claims.ExpiresAt.Time
	// allow 1s tolerance for JWT second-precision timestamps
	if expiry.Before(before.Add(ttl).Add(-time.Second)) || expiry.After(after.Add(ttl).Add(time.Second)) {
		t.Errorf("expiry %v not within expected range", expiry)
	}
}

func TestJWKS_ContainsPublicKey(t *testing.T) {
	issuer := newTestIssuer(t)
	jwks := issuer.JWKS()

	if len(jwks.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(jwks.Keys))
	}
	k := jwks.Keys[0]
	if k.Kty != "RSA" {
		t.Errorf("kty: got %q, want RSA", k.Kty)
	}
	if k.Alg != "RS256" {
		t.Errorf("alg: got %q, want RS256", k.Alg)
	}
	if k.Kid != "test-key-1" {
		t.Errorf("kid: got %q, want test-key-1", k.Kid)
	}
	if k.N == "" || k.E == "" {
		t.Error("expected non-empty N and E")
	}
}
