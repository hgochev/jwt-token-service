package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/hgochev/jwt-token-service/internal/token"
)

func main() {
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

	fmt.Println(signedToken)

	pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatalf("marshal public key: %v", err)
	}

	pubKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubKeyBytes,
	})

	fmt.Println(string(pubKeyPEM))
}
