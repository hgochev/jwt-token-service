package main

import (
	"crypto/rand"
	"crypto/rsa"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hgochev/jwt-token-service/internal/handlers"
	"github.com/hgochev/jwt-token-service/internal/token"
)

func main() {

	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatalf("generate signing key: %v", err)
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
	apiRouter.POST("/api/jwt/create", handlers.CreateTokenHandler(issuer))
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
