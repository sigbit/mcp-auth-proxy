package mcpproxy

import (
	"crypto/rand"
	"crypto/rsa"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/idp"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/proxy"
	"github.com/stretchr/testify/require"
)

func writeAllowedUsersFile(t *testing.T, path, content string) {
	t.Helper()
	tmp := path + ".tmp"
	require.NoError(t, os.WriteFile(tmp, []byte(content), 0o600))
	require.NoError(t, os.Rename(tmp, path))
}

func TestLoadAllowedUsersFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed-users")
	writeAllowedUsersFile(t, path, "alice@example.com\n")
	option := func(change func(*allowedUsersFileOption)) []allowedUsersFileOption {
		o := allowedUsersFileOption{provider: "google", flag: "--google-allowed-users-file", path: path, configured: true}
		change(&o)
		return []allowedUsersFileOption{o}
	}

	t.Run("unset option changes nothing", func(t *testing.T) {
		files, err := loadAllowedUsersFiles(option(func(o *allowedUsersFileOption) { o.path = ""; o.otherRules = true }))
		require.NoError(t, err)
		require.Empty(t, files)
	})

	t.Run("file is loaded for its provider", func(t *testing.T) {
		files, err := loadAllowedUsersFiles(option(func(o *allowedUsersFileOption) {}))
		require.NoError(t, err)
		require.Len(t, files, 1)
		require.True(t, files.Allows("google", "alice@example.com"))
		require.False(t, files.Allows("google", "bob@example.com"))
	})

	t.Run("provider not configured", func(t *testing.T) {
		_, err := loadAllowedUsersFiles(option(func(o *allowedUsersFileOption) { o.configured = false }))
		require.ErrorContains(t, err, "--google-allowed-users-file")
		require.ErrorContains(t, err, "not configured")
	})

	t.Run("combined with another allow-list option", func(t *testing.T) {
		_, err := loadAllowedUsersFiles(option(func(o *allowedUsersFileOption) { o.otherRules = true }))
		require.ErrorContains(t, err, "--google-allowed-users-file")
		require.ErrorContains(t, err, "cannot be combined")
	})

	t.Run("missing file", func(t *testing.T) {
		_, err := loadAllowedUsersFiles(option(func(o *allowedUsersFileOption) { o.path = filepath.Join(t.TempDir(), "missing") }))
		require.ErrorContains(t, err, "--google-allowed-users-file")
		require.ErrorContains(t, err, "allowed users file")
	})
}

func TestAllowedUsersClaimsAuthorizer(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed-users")
	writeAllowedUsersFile(t, path, "alice@example.com\n")
	file, err := auth.NewAllowedUsersFile(path)
	require.NoError(t, err)
	authorize := allowedUsersClaimsAuthorizer(auth.AllowedUsersFiles{"google": file})

	for _, tt := range []struct {
		name   string
		claims jwt.MapClaims
		want   bool
	}{
		{name: "listed user", claims: jwt.MapClaims{"sub": "alice@example.com", idp.ProviderClaim: "google"}, want: true},
		{name: "unlisted user", claims: jwt.MapClaims{"sub": "bob@example.com", idp.ProviderClaim: "google"}, want: false},
		{name: "other provider is not restricted", claims: jwt.MapClaims{"sub": "bob", idp.ProviderClaim: "github"}, want: true},
		{name: "password login is not restricted", claims: jwt.MapClaims{"sub": auth.PasswordUserID, idp.ProviderClaim: auth.PasswordProvider}, want: true},
		{name: "token without provider, listed", claims: jwt.MapClaims{"sub": "alice@example.com"}, want: true},
		{name: "token without provider, unlisted", claims: jwt.MapClaims{"sub": "bob@example.com"}, want: false},
		{name: "missing subject", claims: jwt.MapClaims{idp.ProviderClaim: "google"}, want: false},
		{name: "non-string subject", claims: jwt.MapClaims{"sub": 42, idp.ProviderClaim: "google"}, want: false},
		{name: "non-string provider falls back to all files", claims: jwt.MapClaims{"sub": "bob@example.com", idp.ProviderClaim: 42}, want: false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, authorize(tt.claims))
		})
	}
}

// End to end with the real pieces: allowed users file -> claims authorizer ->
// proxy router. A token that stays cryptographically valid is refused on the
// next request once its user is removed from the file, and the backend is not
// reached.
func TestAllowedUsersFile_RemovedUserIsRefusedOnNextRequest(t *testing.T) {
	const issuer = "https://example.com"
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "allowed-users")
	writeAllowedUsersFile(t, path, "alice@example.com\nbob@example.com\n")
	files, err := loadAllowedUsersFiles([]allowedUsersFileOption{
		{provider: "google", flag: "--google-allowed-users-file", path: path, configured: true},
	})
	require.NoError(t, err)

	backendHits := 0
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		backendHits++
		w.WriteHeader(http.StatusOK)
	})
	pr, err := proxy.NewProxyRouter(issuer, backend, &key.PublicKey, http.Header{}, false, false, nil, "/userinfo")
	require.NoError(t, err)
	pr.SetClaimsAuthorizer(allowedUsersClaimsAuthorizer(files))
	gin.SetMode(gin.TestMode)
	router := gin.New()
	pr.SetupRoutes(router)

	bearer := func(provider, user string) string {
		claims := jwt.MapClaims{
			"iss": issuer, "aud": issuer, "sub": user,
			"exp": time.Now().Add(time.Hour).Unix(),
		}
		if provider != "" {
			claims[idp.ProviderClaim] = provider
		}
		token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
		require.NoError(t, err)
		return token
	}
	do := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		return w
	}
	alice, bob := bearer("google", "alice@example.com"), bearer("google", "bob@example.com")
	githubUser := bearer("github", "octocat")
	legacyAlice := bearer("", "alice@example.com")

	require.Equal(t, http.StatusOK, do(alice).Code)
	require.Equal(t, http.StatusOK, do(bob).Code)
	require.Equal(t, http.StatusOK, do(legacyAlice).Code, "token issued before the provider claim existed")
	require.Equal(t, http.StatusOK, do(githubUser).Code, "a provider without a file is unaffected")
	require.Equal(t, 4, backendHits)

	writeAllowedUsersFile(t, path, "bob@example.com\n") // alice is removed while her tokens are live
	w := do(alice)
	require.Equal(t, http.StatusUnauthorized, w.Code)
	require.JSONEq(t, `{"error":"Invalid token"}`, w.Body.String())
	require.Contains(t, w.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	require.Equal(t, http.StatusUnauthorized, do(legacyAlice).Code)
	require.Equal(t, 4, backendHits, "the backend must not be reached for a removed user")
	require.Equal(t, http.StatusOK, do(bob).Code, "other users keep working")

	require.Equal(t, http.StatusUnauthorized, do(bearer("google", "mallory@example.com")).Code, "never-listed user")

	require.NoError(t, os.Remove(path)) // unreadable list: fail closed
	require.Equal(t, http.StatusUnauthorized, do(bob).Code)
	require.Equal(t, http.StatusOK, do(githubUser).Code, "a provider without a file is still unaffected")

	writeAllowedUsersFile(t, path, "alice@example.com\nbob@example.com\n")
	require.Equal(t, http.StatusOK, do(alice).Code, "re-adding restores access")
}

func TestRun_AllowedUsersFileMisconfigurationStopsStartup(t *testing.T) {
	originalNewProxyRouter := newProxyRouter
	t.Cleanup(func() { newProxyRouter = originalNewProxyRouter })
	routerCreated := false
	newProxyRouter = func(externalURL string, proxyHandler http.Handler, publicKey *rsa.PublicKey, proxyHeaders http.Header, httpStreamingOnly bool, forwardAuthorizationHeader bool, headerMapping map[string]string, headerMappingBase string) (*proxy.ProxyRouter, error) {
		routerCreated = true
		return originalNewProxyRouter(externalURL, proxyHandler, publicKey, proxyHeaders, httpStreamingOnly, forwardAuthorizationHeader, headerMapping, headerMappingBase)
	}

	existing := filepath.Join(t.TempDir(), "allowed-users")
	writeAllowedUsersFile(t, existing, "alice@example.com\n")
	missing := filepath.Join(t.TempDir(), "missing")

	run := func(googleClientID string, googleAllowedUsers []string, googleFile, githubFile, oidcFile string) error {
		return Run(
			":0", ":0", false, "", "", false, "", "",
			t.TempDir(), "local", "",
			"http://localhost",
			googleClientID, "google-secret", googleAllowedUsers, nil, googleFile,
			"", "", "", "", nil, nil, githubFile,
			"", "", "", nil, "", "", nil, nil, nil, nil, oidcFile, "",
			false, "", "", nil, nil, "", false,
			[]string{"http://example.com"}, false, nil, "/userinfo", "", "",
		)
	}

	for _, tt := range []struct {
		name string
		err  error
		want string
	}{
		{name: "missing file", err: run("google-id", nil, missing, "", ""), want: "--google-allowed-users-file: failed to read allowed users file"},
		{name: "combined with --google-allowed-users", err: run("google-id", []string{"alice@example.com"}, existing, "", ""), want: "--google-allowed-users-file cannot be combined"},
		{name: "google provider not configured", err: run("", nil, existing, "", ""), want: "--google-allowed-users-file is set but the google provider is not configured"},
		{name: "github provider not configured", err: run("google-id", nil, "", existing, ""), want: "--github-allowed-users-file is set but the github provider is not configured"},
		{name: "oidc provider not configured", err: run("google-id", nil, "", "", existing), want: "--oidc-allowed-users-file is set but the oidc provider is not configured"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorContains(t, tt.err, tt.want)
		})
	}
	require.False(t, routerCreated, "a misconfigured allow-list must stop startup before anything is served")
}

// The option keys must match what the providers report as their type, or the
// file would silently not be applied.
func TestAllowedUsersFileProviderTypes(t *testing.T) {
	google, err := auth.NewGoogleProvider("http://localhost", "id", "secret", nil, nil)
	require.NoError(t, err)
	require.Equal(t, "google", google.Type())
	github, err := auth.NewGithubProvider("", "", "id", "secret", "http://localhost", nil, nil)
	require.NoError(t, err)
	require.Equal(t, "github", github.Type())
}
