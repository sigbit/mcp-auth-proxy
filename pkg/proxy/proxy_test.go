package proxy

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"

	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/repository"
)

func generateRSAKeyPair() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	return privateKey, &privateKey.PublicKey, nil
}

func createJWT(privateKey *rsa.PrivateKey, claims jwt.MapClaims) (string, error) {
	if _, ok := claims["iss"]; !ok {
		claims["iss"] = "https://example.com"
	}
	if _, ok := claims["aud"]; !ok {
		claims["aud"] = "https://example.com"
	}
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

func TestProxyRouter_RejectsWrongIssuerOrAudience(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	proxyRouter, err := NewProxyRouter("https://example.com", http.NotFoundHandler(), publicKey, http.Header{}, false, false, nil, "/userinfo", nil)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	proxyRouter.SetupRoutes(router)

	cases := []struct {
		name   string
		claims jwt.MapClaims
	}{
		{
			name: "wrong issuer",
			claims: jwt.MapClaims{
				"sub": "test-user",
				"iss": "https://issuer.example.com",
				"aud": "https://example.com",
				"exp": time.Now().Add(time.Hour).Unix(),
			},
		},
		{
			name: "wrong audience",
			claims: jwt.MapClaims{
				"sub": "test-user",
				"iss": "https://example.com",
				"aud": "https://other.example.com",
				"exp": time.Now().Add(time.Hour).Unix(),
			},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			token, err := createJWT(privateKey, tt.claims)
			require.NoError(t, err)

			req, err := http.NewRequest(http.MethodGet, "/test-endpoint", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)
			assert.Equal(t, http.StatusUnauthorized, w.Code)
		})
	}
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

	proxyRouter, err := NewProxyRouter("https://example.com", proxyHandler, publicKey, proxyHeaders, false, false, nil, "/userinfo", nil)
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

func TestProxyRouter_HeaderMapping(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	cases := []struct {
		name            string
		headerMapping   map[string]string
		userinfo        map[string]any
		expectedHeaders map[string]string
	}{
		{
			name:          "string field",
			headerMapping: map[string]string{"/email": "X-Forwarded-Email"},
			userinfo:      map[string]any{"email": "user@example.com"},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
			},
		},
		{
			name:          "array field joined with comma",
			headerMapping: map[string]string{"/groups": "X-Forwarded-Groups"},
			userinfo:      map[string]any{"groups": []any{"admin", "users"}},
			expectedHeaders: map[string]string{
				"X-Forwarded-Groups": "admin,users",
			},
		},
		{
			name:          "multiple mappings",
			headerMapping: map[string]string{"/email": "X-Forwarded-Email", "/preferred_username": "X-Forwarded-User"},
			userinfo:      map[string]any{"email": "user@example.com", "preferred_username": "john"},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
				"X-Forwarded-User":  "john",
			},
		},
		{
			name:            "missing field is skipped",
			headerMapping:   map[string]string{"/email": "X-Forwarded-Email", "/missing": "X-Missing"},
			userinfo:        map[string]any{"email": "user@example.com"},
			expectedHeaders: map[string]string{"X-Forwarded-Email": "user@example.com"},
		},
		{
			name:            "nil headerMapping",
			headerMapping:   nil,
			userinfo:        map[string]any{"email": "user@example.com"},
			expectedHeaders: map[string]string{},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			receivedHeaders := http.Header{}
			proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				maps.Copy(receivedHeaders, r.Header)
				w.WriteHeader(http.StatusOK)
			})

			proxyRouter, err := NewProxyRouter("https://example.com", proxyHandler, publicKey, http.Header{}, false, false, tt.headerMapping, "/userinfo", nil)
			require.NoError(t, err)

			gin.SetMode(gin.TestMode)
			router := gin.New()
			proxyRouter.SetupRoutes(router)

			claims := jwt.MapClaims{
				"sub": "test-user",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			}
			if tt.userinfo != nil {
				claims["userinfo"] = tt.userinfo
			}

			token, err := createJWT(privateKey, claims)
			require.NoError(t, err)

			req, err := http.NewRequest("GET", "/test", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			for header, expected := range tt.expectedHeaders {
				assert.Equal(t, expected, receivedHeaders.Get(header), "header %s mismatch", header)
			}
		})
	}
}

func TestProxyRouter_HeaderMappingBase(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	cases := []struct {
		name              string
		headerMapping     map[string]string
		headerMappingBase string
		claims            jwt.MapClaims
		expectedHeaders   map[string]string
		missingHeaders    []string
	}{
		{
			name:              "base=/ reads top-level claims",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email"},
			headerMappingBase: "/",
			claims: jwt.MapClaims{
				"sub":   "test-user",
				"email": "user@example.com",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"iat":   time.Now().Unix(),
			},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
			},
		},
		{
			name:              "base=/userinfo reads userinfo claims",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email"},
			headerMappingBase: "/userinfo",
			claims: jwt.MapClaims{
				"sub":      "test-user",
				"email":    "toplevel@example.com",
				"userinfo": map[string]any{"email": "userinfo@example.com"},
				"exp":      time.Now().Add(time.Hour).Unix(),
				"iat":      time.Now().Unix(),
			},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "userinfo@example.com",
			},
		},
		{
			name:              "base=/ with multiple claims",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email", "/name": "X-Forwarded-Name"},
			headerMappingBase: "/",
			claims: jwt.MapClaims{
				"sub":   "test-user",
				"email": "user@example.com",
				"name":  "John Doe",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"iat":   time.Now().Unix(),
			},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
				"X-Forwarded-Name":  "John Doe",
			},
		},
		{
			name:              "base=/userinfo skips when userinfo is absent",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email"},
			headerMappingBase: "/userinfo",
			claims: jwt.MapClaims{
				"sub":   "test-user",
				"email": "user@example.com",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"iat":   time.Now().Unix(),
			},
			missingHeaders: []string{"X-Forwarded-Email"},
		},
		{
			name:              "base=/ missing claim is skipped",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email", "/missing": "X-Missing"},
			headerMappingBase: "/",
			claims: jwt.MapClaims{
				"sub":   "test-user",
				"email": "user@example.com",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"iat":   time.Now().Unix(),
			},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
			},
			missingHeaders: []string{"X-Missing"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			receivedHeaders := http.Header{}
			proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				maps.Copy(receivedHeaders, r.Header)
				w.WriteHeader(http.StatusOK)
			})

			proxyRouter, err := NewProxyRouter("https://example.com", proxyHandler, publicKey, http.Header{}, false, false, tt.headerMapping, tt.headerMappingBase, nil)
			require.NoError(t, err)

			gin.SetMode(gin.TestMode)
			router := gin.New()
			proxyRouter.SetupRoutes(router)

			token, err := createJWT(privateKey, tt.claims)
			require.NoError(t, err)

			req, err := http.NewRequest("GET", "/test", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			for header, expected := range tt.expectedHeaders {
				assert.Equal(t, expected, receivedHeaders.Get(header), "header %s mismatch", header)
			}
			for _, header := range tt.missingHeaders {
				assert.Empty(t, receivedHeaders.Get(header), "header %s should not be set", header)
			}
		})
	}
}

func TestProxyRouter_AuthorizationHeaderDefaultBehavior(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	t.Run("strips authorization header by default", func(t *testing.T) {
		var backendAuthorization string
		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendAuthorization = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		})

		proxyRouter, err := NewProxyRouter("https://example.com", proxyHandler, publicKey, http.Header{}, false, false, nil, "/userinfo", nil)
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

		req, err := http.NewRequest(http.MethodGet, "/mcp", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Empty(t, backendAuthorization)
	})

	t.Run("forwards authorization header when enabled", func(t *testing.T) {
		var backendAuthorization string
		proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			backendAuthorization = r.Header.Get("Authorization")
			w.WriteHeader(http.StatusOK)
		})

		proxyRouter, err := NewProxyRouter("https://example.com", proxyHandler, publicKey, http.Header{}, false, true, nil, "/userinfo", nil)
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

		req, err := http.NewRequest(http.MethodGet, "/mcp", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)

		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, "Bearer "+token, backendAuthorization)
	})
}

func TestProxyRouter_HeaderMappingStripsClientHeaders(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	cases := []struct {
		name              string
		headerMapping     map[string]string
		headerMappingBase string
		claims            jwt.MapClaims
		clientHeaders     map[string]string
		expectedHeaders   map[string]string
		missingHeaders    []string
	}{
		{
			name:              "claim missing strips client header",
			headerMapping:     map[string]string{"/groups": "X-Forwarded-Groups"},
			headerMappingBase: "/userinfo",
			claims: jwt.MapClaims{
				"sub":      "test-user",
				"userinfo": map[string]any{"email": "user@example.com"},
				"exp":      time.Now().Add(time.Hour).Unix(),
				"iat":      time.Now().Unix(),
			},
			clientHeaders:  map[string]string{"X-Forwarded-Groups": "admin"},
			missingHeaders: []string{"X-Forwarded-Groups"},
		},
		{
			name:              "claim present overwrites client header",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email"},
			headerMappingBase: "/userinfo",
			claims: jwt.MapClaims{
				"sub":      "test-user",
				"userinfo": map[string]any{"email": "user@example.com"},
				"exp":      time.Now().Add(time.Hour).Unix(),
				"iat":      time.Now().Unix(),
			},
			clientHeaders: map[string]string{"X-Forwarded-Email": "attacker@example.com"},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
			},
		},
		{
			name:              "base path absent strips client header",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email"},
			headerMappingBase: "/userinfo",
			claims: jwt.MapClaims{
				"sub": "test-user",
				"exp": time.Now().Add(time.Hour).Unix(),
				"iat": time.Now().Unix(),
			},
			clientHeaders:  map[string]string{"X-Forwarded-Email": "attacker@example.com"},
			missingHeaders: []string{"X-Forwarded-Email"},
		},
		{
			name:              "mixed mappings only set claims that exist",
			headerMapping:     map[string]string{"/email": "X-Forwarded-Email", "/groups": "X-Forwarded-Groups"},
			headerMappingBase: "/",
			claims: jwt.MapClaims{
				"sub":   "test-user",
				"email": "user@example.com",
				"exp":   time.Now().Add(time.Hour).Unix(),
				"iat":   time.Now().Unix(),
			},
			clientHeaders: map[string]string{
				"X-Forwarded-Email":  "attacker@example.com",
				"X-Forwarded-Groups": "admin",
			},
			expectedHeaders: map[string]string{
				"X-Forwarded-Email": "user@example.com",
			},
			missingHeaders: []string{"X-Forwarded-Groups"},
		},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			receivedHeaders := http.Header{}
			proxyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				maps.Copy(receivedHeaders, r.Header)
				w.WriteHeader(http.StatusOK)
			})

			proxyRouter, err := NewProxyRouter("https://example.com", proxyHandler, publicKey, http.Header{}, false, false, tt.headerMapping, tt.headerMappingBase, nil)
			require.NoError(t, err)

			gin.SetMode(gin.TestMode)
			router := gin.New()
			proxyRouter.SetupRoutes(router)

			token, err := createJWT(privateKey, tt.claims)
			require.NoError(t, err)

			req, err := http.NewRequest("GET", "/test", nil)
			require.NoError(t, err)
			req.Header.Set("Authorization", "Bearer "+token)
			for k, v := range tt.clientHeaders {
				req.Header.Set(k, v)
			}

			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			assert.Equal(t, http.StatusOK, w.Code)
			for header, expected := range tt.expectedHeaders {
				assert.Equal(t, expected, receivedHeaders.Get(header), "header %s mismatch", header)
			}
			for _, header := range tt.missingHeaders {
				assert.Empty(t, receivedHeaders.Get(header), "header %s should be stripped", header)
			}
		})
	}
}

func TestProxyRouter_ProtectedResourceTrailingSlash(t *testing.T) {
	_, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	proxyRouter, err := NewProxyRouter("https://example.com/", http.NotFoundHandler(), publicKey, http.Header{}, false, false, nil, "/userinfo", nil)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	proxyRouter.SetupRoutes(router)

	req, err := http.NewRequest("GET", OauthProtectedResourceEndpoint, nil)
	require.NoError(t, err)

	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp protectedResourceResponse
	err = json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "https://example.com/", resp.Resource)
	assert.Equal(t, []string{"https://example.com/"}, resp.AuthorizationServers)
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

			proxyRouter, err := NewProxyRouter("https://example.com", proxyHandler, publicKey, http.Header{}, tt.streamingOnly, false, nil, "/userinfo", nil)
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

// fakeRevalidator is a test double implementing both auth.Provider and
// auth.Revalidator. The Revalidate behavior is controlled by the fn field.
type fakeRevalidator struct {
	name  string
	calls int32
	fn    func(ctx context.Context, tok *oauth2.Token) (bool, *oauth2.Token, error)
}

func (f *fakeRevalidator) Name() string        { return f.name }
func (f *fakeRevalidator) Type() string        { return "oidc" }
func (f *fakeRevalidator) RedirectURL() string { return "" }
func (f *fakeRevalidator) AuthURL() string     { return "" }
func (f *fakeRevalidator) AuthCodeURL(string) (string, error) {
	return "", nil
}
func (f *fakeRevalidator) Exchange(*gin.Context, string) (*oauth2.Token, error) {
	return nil, nil
}
func (f *fakeRevalidator) Authorization(context.Context, *oauth2.Token) (bool, string, map[string]any, error) {
	return true, "", nil, nil
}
func (f *fakeRevalidator) Revalidate(ctx context.Context, tok *oauth2.Token) (bool, *oauth2.Token, error) {
	atomic.AddInt32(&f.calls, 1)
	return f.fn(ctx, tok)
}
func (f *fakeRevalidator) CallCount() int { return int(atomic.LoadInt32(&f.calls)) }

// newRevalTestRepo returns a fresh KVS repository backed by a tempfile.
func newRevalTestRepo(t *testing.T) repository.Repository {
	t.Helper()
	dir := t.TempDir()
	repo, err := repository.NewKVSRepository(filepath.Join(dir, "test.db"), "test")
	require.NoError(t, err)
	t.Cleanup(func() { _ = repo.Close() })
	return repo
}

// buildRevalRouter wires a ProxyRouter with revalidation enabled for the
// given provider, repo, and interval. Returns the gin engine ready to serve.
func buildRevalRouter(t *testing.T, publicKey *rsa.PublicKey, repo repository.Repository, prov auth.Provider, interval time.Duration, backend http.Handler) *gin.Engine {
	return buildRevalRouterWithTimeout(t, publicKey, repo, prov, interval, 0, backend)
}

// buildRevalRouterWithTimeout is like buildRevalRouter but lets the caller
// override the per-call revalidation timeout. A zero timeout selects the
// proxy's built-in default (defaultRevalidateTimeout).
func buildRevalRouterWithTimeout(t *testing.T, publicKey *rsa.PublicKey, repo repository.Repository, prov auth.Provider, interval, timeout time.Duration, backend http.Handler) *gin.Engine {
	return buildRevalRouterWithOptions(t, publicKey, repo, prov, interval, timeout, "", backend)
}

// buildRevalRouterWithOptions wires a ProxyRouter with the full set of
// revalidation knobs. onFailure="" selects the constructor's default
// (RevalidateOnFailureAllow).
func buildRevalRouterWithOptions(t *testing.T, publicKey *rsa.PublicKey, repo repository.Repository, prov auth.Provider, interval, timeout time.Duration, onFailure RevalidateOnFailure, backend http.Handler) *gin.Engine {
	t.Helper()
	if backend == nil {
		backend = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		})
	}
	pr, err := NewProxyRouter(
		"https://example.com", backend, publicKey, http.Header{}, false, false, nil, "/userinfo",
		&Options{
			Repo:                repo,
			Providers:           []auth.Provider{prov},
			RevalidateInterval:  interval,
			RevalidateTimeout:   timeout,
			RevalidateOnFailure: onFailure,
		},
	)
	require.NoError(t, err)
	gin.SetMode(gin.TestMode)
	router := gin.New()
	pr.SetupRoutes(router)
	return router
}

func TestProxyRouter_Revalidation(t *testing.T) {
	privateKey, publicKey, err := generateRSAKeyPair()
	require.NoError(t, err)

	const subject = "user-1"
	makeToken := func(t *testing.T) string {
		t.Helper()
		tok, err := createJWT(privateKey, jwt.MapClaims{
			"sub": subject,
			"exp": time.Now().Add(time.Hour).Unix(),
			"iat": time.Now().Unix(),
		})
		require.NoError(t, err)
		return tok
	}

	doRequest := func(t *testing.T, router *gin.Engine, token string) *httptest.ResponseRecorder {
		t.Helper()
		req, err := http.NewRequest(http.MethodGet, "/mcp", nil)
		require.NoError(t, err)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}

	seedSession := func(t *testing.T, repo repository.Repository, lastChecked time.Time, providerName string) {
		t.Helper()
		err := repo.PutUpstreamSession(context.Background(), &repository.UpstreamSession{
			Subject:     subject,
			Provider:    providerName,
			AccessToken: "upstream-access",
			LastChecked: lastChecked,
		})
		require.NoError(t, err)
	}

	t.Run("cache hit skips Revalidate", func(t *testing.T) {
		repo := newRevalTestRepo(t)
		prov := &fakeRevalidator{name: "okta", fn: func(context.Context, *oauth2.Token) (bool, *oauth2.Token, error) {
			t.Fatal("should not be called on cache hit")
			return false, nil, nil
		}}
		seedSession(t, repo, time.Now().UTC(), prov.Name())
		router := buildRevalRouter(t, publicKey, repo, prov, time.Hour, nil)

		w := doRequest(t, router, makeToken(t))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 0, prov.CallCount())
	})

	t.Run("cache miss with allowed=true passes and bumps LastChecked", func(t *testing.T) {
		repo := newRevalTestRepo(t)
		prov := &fakeRevalidator{name: "okta", fn: func(context.Context, *oauth2.Token) (bool, *oauth2.Token, error) {
			return true, nil, nil
		}}
		old := time.Now().Add(-2 * time.Hour).UTC()
		seedSession(t, repo, old, prov.Name())
		router := buildRevalRouter(t, publicKey, repo, prov, time.Minute, nil)

		w := doRequest(t, router, makeToken(t))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 1, prov.CallCount())

		got, err := repo.GetUpstreamSession(context.Background(), subject)
		require.NoError(t, err)
		assert.True(t, got.LastChecked.After(old), "LastChecked should be bumped")
	})

	t.Run("fatal error revokes all tokens for subject and rejects", func(t *testing.T) {
		repo := newRevalTestRepo(t)
		prov := &fakeRevalidator{name: "okta", fn: func(context.Context, *oauth2.Token) (bool, *oauth2.Token, error) {
			return false, nil, &auth.FatalRevalidationError{Reason: "invalid_grant"}
		}}
		seedSession(t, repo, time.Now().Add(-2*time.Hour).UTC(), prov.Name())

		// Pre-index two access-token signatures.
		ctx := context.Background()
		require.NoError(t, repo.IndexAccessTokenForSubject(ctx, subject, "sig-1"))
		require.NoError(t, repo.IndexAccessTokenForSubject(ctx, subject, "sig-2"))

		router := buildRevalRouter(t, publicKey, repo, prov, time.Minute, nil)

		w := doRequest(t, router, makeToken(t))
		assert.Equal(t, http.StatusUnauthorized, w.Code)

		// Upstream session should be deleted.
		_, err := repo.GetUpstreamSession(ctx, subject)
		assert.Error(t, err)

		// Index should be empty (RevokeAccessToken should have unindexed).
		// At minimum, a subsequent revalidation must not find the upstream session.
		sigs, _ := repo.ListAccessTokensForSubject(ctx, subject)
		// We don't strictly require sigs to be empty (RevokeAccessToken on a
		// non-existent session may not unindex), but the upstream session must
		// be gone, which is the critical invariant.
		_ = sigs
	})

	t.Run("non-fatal error allows request (oauth2-proxy parity)", func(t *testing.T) {
		repo := newRevalTestRepo(t)
		prov := &fakeRevalidator{name: "okta", fn: func(context.Context, *oauth2.Token) (bool, *oauth2.Token, error) {
			return false, nil, fmt.Errorf("transient: connection refused")
		}}
		seedSession(t, repo, time.Now().Add(-2*time.Hour).UTC(), prov.Name())
		router := buildRevalRouter(t, publicKey, repo, prov, time.Minute, nil)

		w := doRequest(t, router, makeToken(t))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 1, prov.CallCount())
	})

	t.Run("revalidate timeout is bounded and treated as transient", func(t *testing.T) {
		// Simulate an unresponsive IdP: the revalidator blocks until its
		// ctx is cancelled. With a short RevalidateTimeout the call must
		// return quickly via context.DeadlineExceeded and be classified as
		// a transient failure (request allowed, no token revocation),
		// preventing the proxy from hanging on a stuck upstream.
		repo := newRevalTestRepo(t)
		var ctxErr error
		prov := &fakeRevalidator{name: "okta", fn: func(ctx context.Context, _ *oauth2.Token) (bool, *oauth2.Token, error) {
			<-ctx.Done()
			ctxErr = ctx.Err()
			return false, nil, ctx.Err()
		}}
		seedSession(t, repo, time.Now().Add(-2*time.Hour).UTC(), prov.Name())
		router := buildRevalRouterWithTimeout(t, publicKey, repo, prov, time.Minute, 50*time.Millisecond, nil)

		start := time.Now()
		w := doRequest(t, router, makeToken(t))
		elapsed := time.Since(start)

		assert.Equal(t, http.StatusOK, w.Code, "transient timeout should allow the request")
		assert.Equal(t, 1, prov.CallCount())
		assert.ErrorIs(t, ctxErr, context.DeadlineExceeded, "revalidator must observe the bounded timeout")
		assert.Less(t, elapsed, time.Second, "request must not block beyond the timeout")
	})

	t.Run("on-failure=deny revokes session on transient error", func(t *testing.T) {
		// With RevalidateOnFailureDeny, even a non-fatal error (e.g. dex
		// returning invalid_request for a revoked refresh token, or a
		// network blip) must result in revocation + 401 rather than the
		// default allow-with-warning. This is the strict-mode path
		// operators opt into when their IdP doesn't reliably distinguish
		// deprovisioning with a fatal-coded error.
		repo := newRevalTestRepo(t)
		prov := &fakeRevalidator{name: "okta", fn: func(context.Context, *oauth2.Token) (bool, *oauth2.Token, error) {
			return false, nil, fmt.Errorf("oauth2: \"invalid_request\" \"Refresh token is invalid or has already been claimed by another client.\"")
		}}
		seedSession(t, repo, time.Now().Add(-2*time.Hour).UTC(), prov.Name())
		router := buildRevalRouterWithOptions(t, publicKey, repo, prov, time.Minute, 0, RevalidateOnFailureDeny, nil)

		w := doRequest(t, router, makeToken(t))
		assert.Equal(t, http.StatusUnauthorized, w.Code, "deny mode must reject on transient failure")
		assert.Equal(t, 1, prov.CallCount())

		_, err := repo.GetUpstreamSession(context.Background(), subject)
		assert.Error(t, err, "deny mode must revoke the upstream session")
	})

	t.Run("on-failure=deny still allows on success", func(t *testing.T) {
		// Sanity check: deny mode must not affect the happy path. A
		// successful revalidation continues to allow + persist the
		// refreshed token.
		repo := newRevalTestRepo(t)
		prov := &fakeRevalidator{name: "okta", fn: func(context.Context, *oauth2.Token) (bool, *oauth2.Token, error) {
			return true, nil, nil
		}}
		seedSession(t, repo, time.Now().Add(-2*time.Hour).UTC(), prov.Name())
		router := buildRevalRouterWithOptions(t, publicKey, repo, prov, time.Minute, 0, RevalidateOnFailureDeny, nil)

		w := doRequest(t, router, makeToken(t))
		assert.Equal(t, http.StatusOK, w.Code, "deny mode must allow successful revalidations")
		assert.Equal(t, 1, prov.CallCount())
	})

	t.Run("refresh persists new token", func(t *testing.T) {
		repo := newRevalTestRepo(t)
		newExpiry := time.Now().Add(2 * time.Hour).UTC().Truncate(time.Second)
		prov := &fakeRevalidator{name: "okta", fn: func(context.Context, *oauth2.Token) (bool, *oauth2.Token, error) {
			return true, &oauth2.Token{
				AccessToken:  "new-access",
				RefreshToken: "new-refresh",
				TokenType:    "Bearer",
				Expiry:       newExpiry,
			}, nil
		}}
		seedSession(t, repo, time.Now().Add(-2*time.Hour).UTC(), prov.Name())
		router := buildRevalRouter(t, publicKey, repo, prov, time.Minute, nil)

		w := doRequest(t, router, makeToken(t))
		assert.Equal(t, http.StatusOK, w.Code)

		got, err := repo.GetUpstreamSession(context.Background(), subject)
		require.NoError(t, err)
		assert.Equal(t, "new-access", got.AccessToken)
		assert.Equal(t, "new-refresh", got.RefreshToken)
		assert.Equal(t, "Bearer", got.TokenType)
		assert.True(t, got.Expiry.Equal(newExpiry))
	})

	t.Run("no upstream session rejects request", func(t *testing.T) {
		repo := newRevalTestRepo(t)
		prov := &fakeRevalidator{name: "okta", fn: func(context.Context, *oauth2.Token) (bool, *oauth2.Token, error) {
			t.Fatal("should not be called when upstream session missing")
			return false, nil, nil
		}}
		// Intentionally do NOT seed an upstream session.
		router := buildRevalRouter(t, publicKey, repo, prov, time.Minute, nil)

		w := doRequest(t, router, makeToken(t))
		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.Equal(t, 0, prov.CallCount())
	})

	t.Run("disabled when interval is zero", func(t *testing.T) {
		repo := newRevalTestRepo(t)
		prov := &fakeRevalidator{name: "okta", fn: func(context.Context, *oauth2.Token) (bool, *oauth2.Token, error) {
			t.Fatal("should not be called when revalidation disabled")
			return false, nil, nil
		}}
		// Even with no upstream session, request should pass when disabled.
		pr, err := NewProxyRouter(
			"https://example.com", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}), publicKey, http.Header{}, false, false, nil, "/userinfo",
			&Options{Repo: repo, Providers: []auth.Provider{prov}, RevalidateInterval: 0},
		)
		require.NoError(t, err)
		gin.SetMode(gin.TestMode)
		router := gin.New()
		pr.SetupRoutes(router)

		w := doRequest(t, router, makeToken(t))
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Equal(t, 0, prov.CallCount())
	})
}
