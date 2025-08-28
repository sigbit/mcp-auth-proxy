package idp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/pkg/repository"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
)

func setupTestServer(t *testing.T) (*httptest.Server, repository.Repository, string) {
	// Create temp directory and repository
	tmpDir, err := os.MkdirTemp("", "idp_test_*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	dbPath := filepath.Join(tmpDir, "test.db")
	repo, err := repository.NewKVSRepository(dbPath, "test")
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	secret := sha256.Sum256([]byte("test_secret"))

	// Generate RSA key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	// Setup IDP router
	gin.SetMode(gin.TestMode)
	router := gin.New()

	// Session middleware
	store := cookie.NewStore(secret[:])
	router.Use(sessions.Sessions("test_session", store))

	// Mock auth middleware that always passes
	router.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(auth.SessionKeyAuthorized, true)
		err := session.Save()
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to save session"})
			c.Abort()
			return
		}
		c.Next()
	})

	// Create auth router and IDP router
	authRouter, err := auth.NewAuthRouter([]string{}, false)
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	idpRouter, err := NewIDPRouter(repo, privKey, logger, "", secret[:], authRouter)
	require.NoError(t, err)

	idpRouter.SetupRoutes(router)

	// Start test server
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	return server, repo, tmpDir
}

func TestOAuthServerMetadata(t *testing.T) {
	server, _, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + OauthAuthorizationServerEndpoint)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var metadata map[string]any
	err = json.NewDecoder(resp.Body).Decode(&metadata)
	require.NoError(t, err)

	// Verify OAuth server metadata
	require.Equal(t, Issuer, metadata["issuer"])
	authEndpoint, ok := metadata["authorization_endpoint"].(string)
	require.True(t, ok)
	require.Contains(t, authEndpoint, ".idp/auth")

	tokenEndpoint, ok := metadata["token_endpoint"].(string)
	require.True(t, ok)
	require.Contains(t, tokenEndpoint, ".idp/token")

	grantTypes, ok := metadata["grant_types_supported"].([]any)
	require.True(t, ok)
	require.Contains(t, grantTypes, "authorization_code")
	require.Contains(t, grantTypes, "refresh_token")

	responseTypes, ok := metadata["response_types_supported"].([]any)
	require.True(t, ok)
	require.Contains(t, responseTypes, "code")
}

func TestJWKSEndpoint(t *testing.T) {
	server, _, _ := setupTestServer(t)

	resp, err := http.Get(server.URL + JWKSEndpoint)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)

	var jwks map[string]any
	err = json.NewDecoder(resp.Body).Decode(&jwks)
	require.NoError(t, err)

	keys, ok := jwks["keys"].([]any)
	require.True(t, ok)
	require.Len(t, keys, 1)

	key := keys[0].(map[string]any)
	require.Equal(t, "RSA", key["kty"])
	require.Equal(t, "sig", key["use"])
	require.Equal(t, "RS256", key["alg"])
	require.NotEmpty(t, key["kid"])
	require.NotEmpty(t, key["n"])
	require.NotEmpty(t, key["e"])
}

func TestPrivateClient(t *testing.T) {
	server, _, _ := setupTestServer(t)

	// Register a test client using the registration endpoint
	regReq := registrationRequest{
		ClientName:              "Private OAuth Client",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Scope:                   "test",
		RedirectURIs:            []string{"http://localhost:8080/callback"},
	}

	reqBody, err := json.Marshal(regReq)
	require.NoError(t, err)

	resp, err := http.Post(server.URL+RegistrationEndpoint, "application/json", bytes.NewReader(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var regResp registrationResponse
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	require.NoError(t, err)

	config := &oauth2.Config{
		ClientID:     regResp.ClientID,
		ClientSecret: regResp.ClientSecret,
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + AuthorizationEndpoint,
			TokenURL: server.URL + TokenEndpoint,
		},
	}
	state := "test-state"
	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Step 1: Make initial authorization request
	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()

	// Should get a redirect to the authorization return endpoint
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authResp.StatusCode)
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)
	require.Contains(t, location, strings.ReplaceAll(AuthorizationReturnEndpoint, ":ar_id", ""))

	// Step 2: Follow the redirect to complete authorization
	authReturnResp, err := client.Get(server.URL + location)
	require.NoError(t, err)
	defer authReturnResp.Body.Close()

	// Should get another redirect with authorization code
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authReturnResp.StatusCode)
	callbackLocation := authReturnResp.Header.Get("Location")
	require.NotEmpty(t, callbackLocation)

	// Step 3: Extract authorization code from callback URL
	callbackURL, err := url.Parse(callbackLocation)
	require.NoError(t, err)
	code := callbackURL.Query().Get("code")
	require.NotEmpty(t, code)
	receivedState := callbackURL.Query().Get("state")
	require.Equal(t, state, receivedState)

	// Step 4: Exchange authorization code for tokens using manual HTTP request
	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", code)
	tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
	tokenReq.Set("client_id", regResp.ClientID)
	tokenReq.Set("client_secret", regResp.ClientSecret)

	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	// Should get a valid token response
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult map[string]any
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	require.NoError(t, err)

	accessToken, ok := tokenResult["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, accessToken)

	refreshToken, ok := tokenResult["refresh_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, refreshToken)

	tokenType, ok := tokenResult["token_type"].(string)
	require.True(t, ok)
	require.Equal(t, "bearer", tokenType)

	// Step 5: Test token refresh functionality using manual HTTP request
	originalAccessToken := accessToken

	refreshReq := url.Values{}
	refreshReq.Set("grant_type", "refresh_token")
	refreshReq.Set("refresh_token", refreshToken)
	refreshReq.Set("client_id", regResp.ClientID)
	refreshReq.Set("client_secret", regResp.ClientSecret)

	refreshResp, err := http.PostForm(server.URL+TokenEndpoint, refreshReq)
	require.NoError(t, err)
	defer refreshResp.Body.Close()

	require.Equal(t, http.StatusOK, refreshResp.StatusCode)

	var refreshResult map[string]any
	err = json.NewDecoder(refreshResp.Body).Decode(&refreshResult)
	require.NoError(t, err)

	newAccessToken, ok := refreshResult["access_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, newAccessToken)
	require.NotEqual(t, originalAccessToken, newAccessToken, "Access token should be different after refresh")
}
