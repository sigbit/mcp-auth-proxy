package idp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/repository"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

// setupProviderClaimServer is an IdP whose browser session was authenticated
// by the given provider type ("" = a session from before the provider was
// recorded).
func setupProviderClaimServer(t *testing.T, backend, providerType string) *httptest.Server {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "test.db")
	var repo repository.Repository
	var err error
	if backend == "sqlite" {
		repo, err = repository.NewSQLRepository("sqlite", dbPath)
	} else {
		repo, err = repository.NewKVSRepository(dbPath, "test")
	}
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	secret := sha256.Sum256([]byte("test_secret"))
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.Use(sessions.Sessions("test_session", cookie.NewStore(secret[:])))
	router.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(auth.SessionKeyAuthorized, true)
		session.Set(auth.SessionKeyUserID, "test-user@example.com")
		if providerType != "" {
			session.Set(auth.SessionKeyProvider, providerType)
		}
		if err := session.Save(); err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session"})
			return
		}
		c.Next()
	})

	authRouter, err := auth.NewAuthRouter(zap.NewNop(), []string{}, false, nil, auth.NewFlowCookies(secret[:], false))
	require.NoError(t, err)
	idpRouter, err := NewIDPRouter(repo, privKey, zap.NewNop(), "http://localhost:8080", secret[:], authRouter)
	require.NoError(t, err)
	idpRouter.SetupRoutes(router)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server
}

func accessTokenClaims(t *testing.T, tokenResult map[string]any) map[string]any {
	t.Helper()
	accessToken, ok := tokenResult["access_token"].(string)
	require.True(t, ok)
	parts := strings.Split(accessToken, ".")
	require.Len(t, parts, 3)
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)
	var claims map[string]any
	require.NoError(t, json.Unmarshal(payload, &claims))
	return claims
}

func postToken(t *testing.T, serverURL string, form url.Values) map[string]any {
	t.Helper()
	resp, err := http.PostForm(serverURL+TokenEndpoint, form)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var result map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&result))
	return result
}

// The access token names the provider the user signed in with, and keeps
// naming it when the token is refreshed.
func TestAccessTokenProviderClaim(t *testing.T) {
	for _, backend := range []string{"kvs", "sqlite"} {
		for _, providerType := range []string{"google", "github", "oidc", auth.PasswordProvider, ""} {
			name := backend + "/" + providerType
			if providerType == "" {
				name = backend + "/session without provider"
			}
			t.Run(name, func(t *testing.T) {
				server := setupProviderClaimServer(t, backend, providerType)
				regResp := registerTestClient(t, server.URL)
				config := &oauth2.Config{
					ClientID:     regResp.ClientID,
					ClientSecret: regResp.ClientSecret,
					RedirectURL:  "http://localhost:8080/callback",
					Endpoint: oauth2.Endpoint{
						AuthURL:  server.URL + AuthorizationEndpoint,
						TokenURL: server.URL + TokenEndpoint,
					},
				}
				verifier := oauth2.GenerateVerifier()
				callbackURL := testAuthFlowWithURL(t, server.URL, config.AuthCodeURL("test-state", oauth2.S256ChallengeOption(verifier)))

				check := func(claims map[string]any) {
					require.Equal(t, "test-user@example.com", claims["sub"])
					if providerType == "" {
						require.NotContains(t, claims, ProviderClaim)
					} else {
						require.Equal(t, providerType, claims[ProviderClaim])
					}
				}

				tokenResult := postToken(t, server.URL, url.Values{
					"grant_type":    {"authorization_code"},
					"code":          {callbackURL.Query().Get("code")},
					"redirect_uri":  {"http://localhost:8080/callback"},
					"client_id":     {regResp.ClientID},
					"client_secret": {regResp.ClientSecret},
					"code_verifier": {verifier},
				})
				check(accessTokenClaims(t, tokenResult))

				refreshToken, ok := tokenResult["refresh_token"].(string)
				require.True(t, ok)
				refreshResult := postToken(t, server.URL, url.Values{
					"grant_type":    {"refresh_token"},
					"refresh_token": {refreshToken},
					"client_id":     {regResp.ClientID},
					"client_secret": {regResp.ClientSecret},
				})
				check(accessTokenClaims(t, refreshResult))
			})
		}
	}
}
