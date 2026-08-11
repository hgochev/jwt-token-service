package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hgochev/jwt-token-service/internal/token"
)

type tokenRequest struct {
	Subject  string `json:"subject" binding:"required"`
	Audience string `json:"audience" binding:"required"`
	Scope    string `json:"scope"`
}

func CreateTokenHandler(issuer *token.Issuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req tokenRequest
		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		signedToken, err := issuer.Issue(req.Subject, req.Audience, req.Scope)
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
