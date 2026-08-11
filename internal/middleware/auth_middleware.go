package middleware

import (
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/hgochev/jwt-token-service/internal/auth"
)

func AuthMiddleware() gin.HandlerFunc {
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

		err := auth.ValidateToken(c.Request.Context(), tokenString)

		if err != nil {
			log.Printf("token validation failed: %v", err)
			c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid kubernetes token"})
			c.Abort()
			return
		}
	}
}
