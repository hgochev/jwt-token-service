package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hgochev/jwt-token-service/internal/token"
)

func CreateTokenHandler(issuer *token.Issuer) gin.HandlerFunc {
	return func(c *gin.Context) {

		signedToken, err := issuer.Issue(
			"system:serviceaccount:payments:payment-api",
			"orders-api",
			"orders:read",
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"token": signedToken})
	}
}

func CreateJWKSHandler(issuer *token.Issuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, issuer.JWKS())
	}
}
