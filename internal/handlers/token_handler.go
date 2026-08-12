package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/hgochev/jwt-token-service/internal/middleware"
	"github.com/hgochev/jwt-token-service/internal/token"
)

type tokenRequest struct {
	Audience string `json:"audience" binding:"required"`
	Scope    string `json:"scope"`
}

func CreateTokenHandler(issuer *token.Issuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		var req tokenRequest

		if err := c.ShouldBindJSON(&req); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error": err.Error(),
			})
			return
		}

		subject, exists := c.Get(middleware.AuthenticatedUserKey)
		if !exists {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "authenticated user not found",
			})
			return
		}

		username, ok := subject.(string)
		if !ok || username == "" {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "invalid authenticated user",
			})
			return
		}

		signedToken, err := issuer.Issue(
			username,
			req.Audience,
			req.Scope,
		)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{
				"error": "failed to issue token",
			})
			return
		}

		c.JSON(http.StatusCreated, gin.H{
			"token": signedToken,
		})
	}
}

func CreateJWKSHandler(issuer *token.Issuer) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.JSON(http.StatusOK, issuer.JWKS())
	}
}
