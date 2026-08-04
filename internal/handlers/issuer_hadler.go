package handlers

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"log"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hgochev/jwt-token-service/internal/token"
)

func CreateIssuerHandler() gin.HandlerFunc {
	return func(c *gin.Context) {

		privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

		signedToken, err := issuer.Issue(
			"system:serviceaccount:payments:payment-api",
			"orders-api",
			"orders:read",
		)
		if err != nil {
			log.Fatalf("issue token: %v", err)
		}

		c.JSON(http.StatusCreated, gin.H{"token": signedToken})
	}
}
