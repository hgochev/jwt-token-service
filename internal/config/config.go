package config

import (
	"errors"
	"os"
	"time"
)

type Config struct {
	Audience  string
	Scope     string
	IssuerURL string
	KeyID     string
	TokenTTL  time.Duration
}

func Load() (*Config, error) {
	audience := os.Getenv("JWT_AUDIENCE")
	if audience == "" {
		return nil, errors.New("JWT_AUDIENCE environment variable is required")
	}

	issuerURL := os.Getenv("JWT_ISSUER_URL")
	if issuerURL == "" {
		return nil, errors.New("JWT_ISSUER_URL environment variable is required")
	}

	keyID := os.Getenv("JWT_KEY_ID")
	if keyID == "" {
		return nil, errors.New("JWT_KEY_ID environment variable is required")
	}

	tokenTTL := 5 * time.Minute
	if ttlStr := os.Getenv("JWT_TOKEN_TTL"); ttlStr != "" {
		parsed, err := time.ParseDuration(ttlStr)
		if err != nil {
			return nil, errors.New("JWT_TOKEN_TTL must be a valid duration (e.g. 5m, 1h)")
		}
		tokenTTL = parsed
	}

	return &Config{
		Audience:  audience,
		Scope:     os.Getenv("JWT_SCOPE"),
		IssuerURL: issuerURL,
		KeyID:     keyID,
		TokenTTL:  tokenTTL,
	}, nil
}
