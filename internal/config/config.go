package config

import (
	"errors"
	"os"
)

type Config struct {
	Audience string
	Scope    string
}

func Load() (*Config, error) {
	audience := os.Getenv("JWT_AUDIENCE")
	if audience == "" {
		return nil, errors.New("JWT_AUDIENCE environment variable is required")
	}

	return &Config{
		Audience: audience,
		Scope:    os.Getenv("JWT_SCOPE"),
	}, nil
}
