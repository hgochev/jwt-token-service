package main

import (
	"github.com/gin-gonic/gin"
	"github.com/hgochev/jwt-token-service/internal/handlers"
)

func main() {

	var router *gin.Engine = gin.Default()

	router.POST("/jwt/create", handlers.CreateIssuerHandler())

	router.Run(":8080")

	// fmt.Println(signedToken)

	// pubKeyBytes, err := x509.MarshalPKIXPublicKey(&privateKey.PublicKey)
	// if err != nil {
	// 	log.Fatalf("marshal public key: %v", err)
	// }

	// pubKeyPEM := pem.EncodeToMemory(&pem.Block{
	// 	Type:  "PUBLIC KEY",
	// 	Bytes: pubKeyBytes,
	// })

	// fmt.Println(string(pubKeyPEM))
}
