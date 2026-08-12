package middleware

import (
	"context"
	"log"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
)

const AuthenticatedUserKey = "authenticatedUser"

type ValidateFunc func(
	ctx context.Context,
	token string,
) (string, error)

func AuthMiddleware(validate ValidateFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")

		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "Authorization header required",
			})
			c.Abort()
			return
		}

		const bearerPrefix = "Bearer "

		if !strings.HasPrefix(authHeader, bearerPrefix) {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid authorization header format",
			})
			c.Abort()
			return
		}

		tokenString := strings.TrimSpace(
			strings.TrimPrefix(authHeader, bearerPrefix),
		)

		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "bearer token required",
			})
			c.Abort()
			return
		}

		username, err := validate(
			c.Request.Context(),
			tokenString,
		)
		if err != nil {
			log.Printf("token validation failed: %v", err)

			c.JSON(http.StatusUnauthorized, gin.H{
				"error": "invalid or unauthorized kubernetes token",
			})
			c.Abort()
			return
		}

		c.Set(AuthenticatedUserKey, username)

		c.Next()
	}
}
