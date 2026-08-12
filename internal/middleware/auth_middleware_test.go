package middleware_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/hgochev/jwt-token-service/internal/middleware"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newRouter(validate middleware.ValidateFunc) *gin.Engine {
	r := gin.New()
	r.POST("/api/jwt/create", middleware.AuthMiddleware(validate), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	return r
}

func TestAuthMiddleware_MissingHeader(t *testing.T) {
	r := newRouter(func(ctx context.Context, token string) error { return nil })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/jwt/create", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddleware_InvalidFormat(t *testing.T) {
	r := newRouter(func(ctx context.Context, token string) error { return nil })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/jwt/create", nil)
	req.Header.Set("Authorization", "Token abc123")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestAuthMiddleware_ValidToken(t *testing.T) {
	r := newRouter(func(ctx context.Context, token string) error { return nil })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/jwt/create", nil)
	req.Header.Set("Authorization", "Bearer valid-token")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
}

func TestAuthMiddleware_InvalidToken(t *testing.T) {
	r := newRouter(func(ctx context.Context, token string) error { return errors.New("not authorized") })

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/jwt/create", nil)
	req.Header.Set("Authorization", "Bearer bad-token")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
