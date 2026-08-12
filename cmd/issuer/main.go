package main

import (
	"crypto/x509"
	"encoding/pem"
	"log"
	"os"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hgochev/jwt-token-service/internal/auth"
	"github.com/hgochev/jwt-token-service/internal/config"
	"github.com/hgochev/jwt-token-service/internal/handlers"
	"github.com/hgochev/jwt-token-service/internal/middleware"
	"github.com/hgochev/jwt-token-service/internal/token"
)

func main() {
	cfg, err := config.Load()
	if err != nil {
		log.Fatalf("load config: %v", err)
	}

	keyBites, err := os.ReadFile("/etc/jwt/private.key")
	if err != nil {
		log.Fatalf("Error loading private key: %v", err)
	}

	block, _ := pem.Decode(keyBites)
	privateKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)

	if err != nil {
		log.Fatalf("Error parcing private key: %v", err)
	}

	issuer, err := token.NewIssuer(
		"https://tokens.example.local",
		"development-key-1",
		privateKey,
		5*time.Minute,
	)

	if err != nil {
		log.Fatalf("create token issuer: %v", err)
	}
	// internal API — token issuance
	apiRouter := gin.Default()
	apiRouter.POST("/api/jwt/create", middleware.AuthMiddleware(auth.ValidateToken), handlers.CreateTokenHandler(issuer, cfg))
	apiRouter.GET("/healthz", handlers.HealthCheckHandler())

	// public metadata — JWKS discovery
	metaRouter := gin.Default()
	metaRouter.GET("/.well-known/jwks.json", handlers.CreateJWKSHandler(issuer))

	// start both servers concurrently
	go func() {
		if err := metaRouter.Run(":8081"); err != nil {
			log.Fatalf("metadata server: %v", err)
		}
	}()

	if err := apiRouter.Run(":8080"); err != nil {
		log.Fatalf("api server: %v", err)
	}
}
