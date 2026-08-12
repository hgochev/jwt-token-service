package handlers_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/hgochev/jwt-token-service/internal/handlers"
	"github.com/hgochev/jwt-token-service/internal/token"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func newTestIssuer(t *testing.T) *token.Issuer {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	issuer, err := token.NewIssuer("https://issuer.test", "test-key-1", key, 5*time.Minute)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return issuer
}

func TestHealthCheckHandler(t *testing.T) {
	r := gin.New()
	r.GET("/healthz", handlers.HealthCheckHandler())

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
}

func TestCreateTokenHandler_Valid(t *testing.T) {
	r := gin.New()
	r.POST("/api/jwt/create", handlers.CreateTokenHandler(newTestIssuer(t)))

	body, _ := json.Marshal(map[string]string{
		"subject":  "system:serviceaccount:payments:payment-api",
		"audience": "orders-api",
		"scope":    "orders:read",
	})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/jwt/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusCreated)
	}
	var resp map[string]string
	json.NewDecoder(w.Body).Decode(&resp)
	if resp["token"] == "" {
		t.Error("expected non-empty token in response")
	}
}

func TestCreateTokenHandler_MissingSubject(t *testing.T) {
	r := gin.New()
	r.POST("/api/jwt/create", handlers.CreateTokenHandler(newTestIssuer(t)))

	body, _ := json.Marshal(map[string]string{"audience": "orders-api"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/jwt/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateTokenHandler_MissingAudience(t *testing.T) {
	r := gin.New()
	r.POST("/api/jwt/create", handlers.CreateTokenHandler(newTestIssuer(t)))

	body, _ := json.Marshal(map[string]string{"subject": "my-service"})
	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/jwt/create", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateTokenHandler_InvalidJSON(t *testing.T) {
	r := gin.New()
	r.POST("/api/jwt/create", handlers.CreateTokenHandler(newTestIssuer(t)))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/jwt/create", bytes.NewReader([]byte("not-json")))
	req.Header.Set("Content-Type", "application/json")
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusBadRequest)
	}
}

func TestCreateJWKSHandler(t *testing.T) {
	r := gin.New()
	r.GET("/.well-known/jwks.json", handlers.CreateJWKSHandler(newTestIssuer(t)))

	w := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil)
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status: got %d, want %d", w.Code, http.StatusOK)
	}
	var resp map[string]interface{}
	json.NewDecoder(w.Body).Decode(&resp)
	keys, ok := resp["keys"].([]interface{})
	if !ok || len(keys) == 0 {
		t.Error("expected non-empty keys array in JWKS response")
	}
}
