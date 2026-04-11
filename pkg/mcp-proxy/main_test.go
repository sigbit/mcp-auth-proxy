package mcpproxy

import (
	"crypto/rsa"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/pkg/proxy"
	"github.com/stretchr/testify/require"
)

func TestRun_NormalizesExternalURLTrailingSlash(t *testing.T) {
	originalNewProxyRouter := newProxyRouter
	t.Cleanup(func() {
		newProxyRouter = originalNewProxyRouter
	})

	cases := []struct {
		name        string
		input       string
		wantURL     string
		wantErr     bool
		errContains string
	}{
		{name: "no trailing slash", input: "https://example.com", wantURL: "https://example.com/"},
		{name: "with trailing slash", input: "https://example.com/", wantURL: "https://example.com/"},
		{name: "with path", input: "https://example.com/foo", wantErr: true, errContains: "must not have a path"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var receivedURL string
			newProxyRouter = func(externalURL string, proxyHandler http.Handler, publicKey *rsa.PublicKey, proxyHeaders http.Header, httpStreamingOnly bool, headerMapping map[string]string) (*proxy.ProxyRouter, error) {
				receivedURL = externalURL
				return nil, errors.New("stop early")
			}

			err := Run(
				":0", ":0", false, "", "", false, "", "",
				t.TempDir(), "local", "",
				tt.input,
				"", "", nil, nil,
				"", "", nil, nil,
				"", "", "", nil, "", "", nil, nil, nil, nil,
				false, "", "", nil, nil, "",
				[]string{"http://example.com"}, false, nil,
			)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				return
			}

			require.Error(t, err)
			require.Contains(t, err.Error(), "stop early")
			require.Equal(t, tt.wantURL, receivedURL)
		})
	}
}

func TestRun_PassesHTTPStreamingOnlyToProxyRouter(t *testing.T) {
	originalNewProxyRouter := newProxyRouter
	t.Cleanup(func() {
		newProxyRouter = originalNewProxyRouter
	})

	var streamingOnlyReceived bool
	newProxyRouter = func(externalURL string, proxyHandler http.Handler, publicKey *rsa.PublicKey, proxyHeaders http.Header, httpStreamingOnly bool, headerMapping map[string]string) (*proxy.ProxyRouter, error) {
		streamingOnlyReceived = httpStreamingOnly
		return nil, errors.New("proxy router init failed")
	}

	err := Run(
		":0",
		":0",
		false,
		"",
		"",
		false,
		"",
		"",
		t.TempDir(),
		"local",
		"",
		"http://localhost",
		"",
		"",
		nil,
		nil,
		"",
		"",
		nil,
		nil,
		"",
		"",
		"",
		nil,
		"",
		"",
		nil,
		nil,
		nil,
		nil,
		false,
		"",
		"",
		nil,
		nil,
		"",
		[]string{"http://example.com"},
		true,
		nil,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create proxy router")
	require.True(t, streamingOnlyReceived, "httpStreamingOnly should be forwarded to proxy router")
}

func TestUserInfoFieldsFromConfig(t *testing.T) {
	t.Run("extracts fields from header mapping and user ID field", func(t *testing.T) {
		fields := userInfoFieldsFromConfig("/email", map[string]string{
			"/email":              "X-Forwarded-Email",
			"/preferred_username": "X-Forwarded-User",
		})
		require.ElementsMatch(t, []string{"email", "preferred_username"}, fields)
	})

	t.Run("handles nested JSON pointers by taking top-level key", func(t *testing.T) {
		fields := userInfoFieldsFromConfig("/email", map[string]string{
			"/address/street": "X-Street",
		})
		require.ElementsMatch(t, []string{"email", "address"}, fields)
	})

	t.Run("deduplicates overlapping fields", func(t *testing.T) {
		fields := userInfoFieldsFromConfig("/email", map[string]string{
			"/email": "X-Forwarded-Email",
		})
		require.Equal(t, []string{"email"}, fields)
	})

	t.Run("empty config returns empty slice", func(t *testing.T) {
		fields := userInfoFieldsFromConfig("", nil)
		require.Empty(t, fields)
	})

	t.Run("handles user ID field without leading slash", func(t *testing.T) {
		fields := userInfoFieldsFromConfig("email", nil)
		require.Equal(t, []string{"email"}, fields)
	})
}

func TestHealthzEndpoint(t *testing.T) {
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Register healthz before auth middleware, same as in Run()
	router.GET("/healthz", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	// Add a catch-all that returns 401 to simulate auth middleware
	router.Use(func(c *gin.Context) {
		c.AbortWithStatus(http.StatusUnauthorized)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest("GET", "/healthz", nil)
	router.ServeHTTP(w, req)

	require.Equal(t, http.StatusOK, w.Code)

	var body map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &body)
	require.NoError(t, err)
	require.Equal(t, "ok", body["status"])
}
