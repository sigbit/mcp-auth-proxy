package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/require"
)

func TestProxyRouter_ClaimsAuthorizerRunsOnEveryRequest(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	backendHits := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits++
		w.WriteHeader(http.StatusOK)
	})
	pr, err := NewProxyRouter("https://example.com", backend, publicKey, http.Header{}, false, false, nil, "/userinfo")
	require.NoError(t, err)

	allowed := map[string]bool{"alice@example.com": true}
	var seen jwt.MapClaims
	pr.SetClaimsAuthorizer(func(claims jwt.MapClaims) bool {
		seen = claims
		sub, _ := claims["sub"].(string)
		return allowed[sub]
	})

	gin.SetMode(gin.TestMode)
	router := gin.New()
	pr.SetupRoutes(router)

	token, err := createJWT(privateKey, jwt.MapClaims{
		"sub":      "alice@example.com",
		"provider": "google",
		"exp":      time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	do := func(bearer string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	require.Equal(t, http.StatusOK, do(token).Code)
	require.Equal(t, 1, backendHits)
	require.Equal(t, "alice@example.com", seen["sub"])
	require.Equal(t, "google", seen["provider"])

	// The same token is still cryptographically valid, but the authorizer
	// no longer accepts its subject.
	delete(allowed, "alice@example.com")
	w := do(token)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.JSONEq(t, `{"error":"Invalid token"}`, w.Body.String())
	require.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	require.Equal(t, 1, backendHits, "the backend must not be reached")

	allowed["alice@example.com"] = true
	require.Equal(t, http.StatusOK, do(token).Code)
	require.Equal(t, 2, backendHits)

	// The authorizer never sees a token that failed verification.
	seen = nil
	require.Equal(t, http.StatusUnauthorized, do("not-a-jwt").Code)
	require.Nil(t, seen)
}

func TestProxyRouter_WithoutClaimsAuthorizer(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	pr, err := NewProxyRouter("https://example.com", backend, publicKey, http.Header{}, false, false, nil, "/userinfo")
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	pr.SetupRoutes(router)

	token, err := createJWT(privateKey, jwt.MapClaims{"sub": "anyone", "exp": time.Now().Add(time.Hour).Unix()})
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	require.Equal(t, http.StatusOK, w.Code)
}
