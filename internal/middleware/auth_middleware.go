package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

type ValidateFunc func(ctx context.Context, token string) error

func AuthMiddleware(validate ValidateFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header requred"})
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(authHeader, "Bearer ")

		if tokenString == "" || tokenString == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header format"})
			c.Abort()
			return
		}

		err := validate(c.Request.Context(), tokenString)

		if err != nil {
			log.Printf("token validation failed: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid kubernetes token"})
			c.Abort()
			return
		}
	}
}
