package proxy

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func createJWT(privateKey *rsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	return token.SignedString(privateKey)
}

func createDummyBackendServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, `{"message": "Hello from backend", "method": "%s", "path": "%s"}`, r.Method, r.URL.Path)
	}))
}

func TestProxyRouter_HandleProxy_ValidToken(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	backendServer := createDummyBackendServer()
	defer backendServer.Close()

	proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		resp, err := http.Get(backendServer.URL + r.URL.Path)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer resp.Body.Close()

		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)

		buf := make([]byte, 1024)
		for {
			n, err := resp.Body.Read(buf)
			if n > 0 {
				w.Write(buf[:n])
			}
			if err != nil {
				break
			}
		}
	})

	proxyHeaders := make(http.Header)
	proxyHeaders.Set("X-Forwarded-By", "mcp-auth-proxy")

	proxyRouter, err := NewProxyRouter("https://example.com", proxyHandler, publicKey, proxyHeaders, false)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	proxyRouter.SetupRoutes(router)

	claims := jwt.MapClaims{
		"sub": "test-user",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}

	token, err := createJWT(privateKey, claims)
	require.NoError(t, err)

	req, err := http.NewRequest("GET", "/test-endpoint", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+token)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusOK, w.Code)

	invalidToken := "invalid"
	req, err = http.NewRequest("GET", "/test-endpoint", nil)
	require.NoError(t, err)
	req.Header.Set("Authorization", "Bearer "+invalidToken)

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusUnauthorized, w.Code)
}

func TestProxyRouter_HTTPStreamingOnlyRejectsSSE(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	cases := []struct {
		name          string
		method        string
		acceptHeader  string
		wantStatus    int
		expectBackend bool
		streamingOnly bool
	}{
		{
			name:          "plain text/event-stream",
			method:        http.MethodGet,
			acceptHeader:  "text/event-stream",
			wantStatus:    http.StatusMethodNotAllowed,
			streamingOnly: true,
		},
		{
			name:          "event-stream with params",
			method:        http.MethodGet,
			acceptHeader:  "text/event-stream; charset=utf-8",
			wantStatus:    http.StatusMethodNotAllowed,
			streamingOnly: true,
		},
		{
			name:          "multiple values",
			method:        http.MethodGet,
			acceptHeader:  "application/json, text/event-stream",
			wantStatus:    http.StatusMethodNotAllowed,
			streamingOnly: true,
		},
		{
			name:          "quality value",
			method:        http.MethodGet,
			acceptHeader:  "text/event-stream;q=0.9",
			wantStatus:    http.StatusMethodNotAllowed,
			streamingOnly: true,
		},
		{
			name:          "post should pass through",
			method:        http.MethodPost,
			acceptHeader:  "text/event-stream",
			wantStatus:    http.StatusOK,
			expectBackend: true,
			streamingOnly: true,
		},
		{
			name:          "get without accept header",
			method:        http.MethodGet,
			acceptHeader:  "",
			wantStatus:    http.StatusOK,
			expectBackend: true,
			streamingOnly: true,
		},
		{
			name:          "get with non-sse accept",
			method:        http.MethodGet,
			acceptHeader:  "application/json",
			wantStatus:    http.StatusOK,
			expectBackend: true,
			streamingOnly: true,
		},
		{
			name:          "sse allowed when streamingOnly disabled",
			method:        http.MethodGet,
			acceptHeader:  "text/event-stream",
			wantStatus:    http.StatusOK,
			expectBackend: true,
			streamingOnly: false,
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			backendCalled := false
			proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				backendCalled = true
				w.WriteHeader(http.StatusOK)
			})

			proxyRouter, err := NewProxyRouter("https://example.com", proxyHandler, publicKey, http.Header{}, tt.streamingOnly)
			require.NoError(t, err)

			gin.SetMode(gin.TestMode)
			router := gin.New()
			proxyRouter.SetupRoutes(router)

			token, err := createJWT(privateKey, jwt.MapClaims{
				"sub": "user",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			})
			require.NoError(t, err)

			req, err := http.NewRequest(tt.method, "/mcp", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)
			req.Header.Set("Accept", tt.acceptHeader)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, tt.wantStatus, w.Code)
			assert.Equal(t, tt.expectBackend, backendCalled, "backend call mismatch")
		})
	}
}
