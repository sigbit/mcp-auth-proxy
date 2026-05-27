package idp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/repository"
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

	// Mock auth middleware that always passes with user identity
	router.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(auth.SessionKeyAuthorized, true)
		session.Set(auth.SessionKeyUserID, "test-user@example.com")
		session.Set(auth.SessionKeyUserInfo, `{"email":"test-user@example.com","name":"Test User"}`)
		err := session.Save()
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to save session"})
			c.Abort()
			return
		}
		c.Next()
	})

	// Create auth router and IDP router
	authRouter, err := auth.NewAuthRouter([]string{}, false, nil)
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	idpRouter, err := NewIDPRouter(repo, privKey, logger, "http://localhost:8080", secret[:], authRouter)
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
	require.Equal(t, "http://localhost:8080", metadata["issuer"])
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

	challengeMethods, ok := metadata["code_challenge_methods_supported"].([]any)
	require.True(t, ok)
	require.Contains(t, challengeMethods, "S256")
	require.NotContains(t, challengeMethods, "plain")
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

	// Step 2: GET renders the authorization confirmation form without granting
	authReturnResp, err := client.Get(server.URL + location)
	require.NoError(t, err)
	defer authReturnResp.Body.Close()
	require.Equal(t, http.StatusOK, authReturnResp.StatusCode)

	// Step 3: POST the confirmation to complete authorization
	authReturnResp, err = client.Post(server.URL+location, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	defer authReturnResp.Body.Close()

	// Should get another redirect with authorization code
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authReturnResp.StatusCode)
	callbackLocation := authReturnResp.Header.Get("Location")
	require.NotEmpty(t, callbackLocation)

	// Step 4: Extract authorization code from callback URL
	callbackURL, err := url.Parse(callbackLocation)
	require.NoError(t, err)
	code := callbackURL.Query().Get("code")
	require.NotEmpty(t, code)
	receivedState := callbackURL.Query().Get("state")
	require.Equal(t, state, receivedState)

	// Step 5: Exchange authorization code for tokens using manual HTTP request
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

	// Step 6: Test token refresh functionality using manual HTTP request
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

// registerTestClient is a helper that registers a private OAuth client and returns the registration response.
func registerTestClient(t *testing.T, serverURL string) registrationResponse {
	t.Helper()

	regReq := registrationRequest{
		ClientName:              "Test OAuth Client",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "client_secret_basic",
		Scope:                   "test",
		RedirectURIs:            []string{"http://localhost:8080/callback"},
	}

	reqBody, err := json.Marshal(regReq)
	require.NoError(t, err)

	resp, err := http.Post(serverURL+RegistrationEndpoint, "application/json", bytes.NewReader(reqBody))
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusCreated, resp.StatusCode)

	var regResp registrationResponse
	err = json.NewDecoder(resp.Body).Decode(&regResp)
	require.NoError(t, err)

	return regResp
}

// testAuthFlowWithURL performs the OAuth authorization flow given a raw authorization URL
// and returns the callback URL after authorization completes.
func testAuthFlowWithURL(t *testing.T, serverURL, authURL string) *url.URL {
	t.Helper()

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

	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authResp.StatusCode,
		"expected redirect, got %d", authResp.StatusCode)
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)
	require.Contains(t, location, strings.ReplaceAll(AuthorizationReturnEndpoint, ":ar_id", ""))

	// Step 2: GET renders the authorization confirmation form without granting
	authReturnResp, err := client.Get(serverURL + location)
	require.NoError(t, err)
	defer authReturnResp.Body.Close()
	require.Equal(t, http.StatusOK, authReturnResp.StatusCode)

	// Step 3: POST the confirmation to complete authorization
	authReturnResp, err = client.Post(serverURL+location, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	defer authReturnResp.Body.Close()

	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authReturnResp.StatusCode,
		"expected redirect with authorization code, got %d", authReturnResp.StatusCode)
	callbackLocation := authReturnResp.Header.Get("Location")
	require.NotEmpty(t, callbackLocation)

	callbackURL, err := url.Parse(callbackLocation)
	require.NoError(t, err)
	require.NotEmpty(t, callbackURL.Query().Get("code"), "callback URL should contain an authorization code")

	return callbackURL
}

func TestAuthorizationReturnRequiresOriginalSession(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"))

	attackerJar, err := cookiejar.New(nil)
	require.NoError(t, err)
	attackerClient := &http.Client{
		Jar: attackerJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authResp, err := attackerClient.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authResp.StatusCode)
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)

	victimJar, err := cookiejar.New(nil)
	require.NoError(t, err)
	victimClient := &http.Client{Jar: victimJar}
	victimResp, err := victimClient.Post(server.URL+location, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	defer victimResp.Body.Close()
	require.Equal(t, http.StatusForbidden, victimResp.StatusCode)
}

func TestPublicClientRequiresPKCE(t *testing.T) {
	server, _, _ := setupTestServer(t)

	regReq := registrationRequest{
		ClientName:              "Public OAuth Client",
		GrantTypes:              []string{"authorization_code", "refresh_token"},
		ResponseTypes:           []string{"code"},
		TokenEndpointAuthMethod: "none",
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
	require.Empty(t, regResp.ClientSecret)

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"))

	client := &http.Client{
		Jar: mustCookieJar(t),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authResp.StatusCode)
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)

	formResp, err := client.Get(server.URL + location)
	require.NoError(t, err)
	defer formResp.Body.Close()
	require.Equal(t, http.StatusOK, formResp.StatusCode)

	authReturnResp, err := client.Post(server.URL+location, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	defer authReturnResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authReturnResp.StatusCode)

	callbackURL, err := url.Parse(authReturnResp.Header.Get("Location"))
	require.NoError(t, err)
	require.Empty(t, callbackURL.Query().Get("code"))
	require.NotEmpty(t, callbackURL.Query().Get("error"))
}

func mustCookieJar(t *testing.T) http.CookieJar {
	t.Helper()
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	return jar
}

func TestAuthWithoutState(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	// Build authorization URL manually WITHOUT a state parameter
	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"))

	callbackURL := testAuthFlowWithURL(t, server.URL, authURL)

	// Server should have generated a state and echoed it back
	require.NotEmpty(t, callbackURL.Query().Get("state"), "server should generate a state when client omits it")

	// Exchange authorization code for tokens
	code := callbackURL.Query().Get("code")
	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", code)
	tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
	tokenReq.Set("client_id", regResp.ClientID)
	tokenReq.Set("client_secret", regResp.ClientSecret)

	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult map[string]any
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	require.NoError(t, err)
	require.NotEmpty(t, tokenResult["access_token"])
}

func TestAuthWithEmptyState(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	// Build authorization URL with an empty state parameter
	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"))

	callbackURL := testAuthFlowWithURL(t, server.URL, authURL)

	// Server should have generated a state and echoed it back
	require.NotEmpty(t, callbackURL.Query().Get("state"), "server should generate a state when client sends empty state")

	// Exchange authorization code for tokens
	code := callbackURL.Query().Get("code")
	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", code)
	tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
	tokenReq.Set("client_id", regResp.ClientID)
	tokenReq.Set("client_secret", regResp.ClientSecret)

	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()

	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult map[string]any
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	require.NoError(t, err)
	require.NotEmpty(t, tokenResult["access_token"])
}

func TestAccessTokenAudienceClaim(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

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

	callbackURL := testAuthFlowWithURL(t, server.URL, config.AuthCodeURL("test-state"))
	code := callbackURL.Query().Get("code")

	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", code)
	tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
	tokenReq.Set("client_id", regResp.ClientID)
	tokenReq.Set("client_secret", regResp.ClientSecret)

	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult map[string]any
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	require.NoError(t, err)

	accessToken := tokenResult["access_token"].(string)

	// Decode JWT payload and verify aud claim contains the external URL
	parts := strings.Split(accessToken, ".")
	require.Len(t, parts, 3, "access token should be a JWT with 3 parts")

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	err = json.Unmarshal(payload, &claims)
	require.NoError(t, err)

	aud, ok := claims["aud"].([]any)
	require.True(t, ok, "aud claim should be present as an array")
	require.Contains(t, aud, "http://localhost:8080", "aud should contain the external URL")
}

// setupTestServerWithKey is like setupTestServer but accepts an existing repository
// and signing key, so a test can simulate a pod restart with a rotated key while
// reusing the prior pod's storage (refresh-token sessions persist there).
func setupTestServerWithKey(t *testing.T, repo repository.Repository, privKey *rsa.PrivateKey) *httptest.Server {
	t.Helper()

	secret := sha256.Sum256([]byte("test_secret"))

	gin.SetMode(gin.TestMode)
	router := gin.New()

	store := cookie.NewStore(secret[:])
	router.Use(sessions.Sessions("test_session", store))

	router.Use(func(c *gin.Context) {
		session := sessions.Default(c)
		session.Set(auth.SessionKeyAuthorized, true)
		session.Set(auth.SessionKeyUserID, "test-user@example.com")
		session.Set(auth.SessionKeyUserInfo, `{"email":"test-user@example.com","name":"Test User"}`)
		if err := session.Save(); err != nil {
			c.JSON(500, gin.H{"error": "Failed to save session"})
			c.Abort()
			return
		}
		c.Next()
	})

	authRouter, err := auth.NewAuthRouter([]string{}, false, nil)
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	idpRouter, err := NewIDPRouter(repo, privKey, logger, "http://localhost:8080", secret[:], authRouter)
	require.NoError(t, err)
	idpRouter.SetupRoutes(router)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server
}

// jwtKID extracts the "kid" header from a compact JWS string.
func jwtKID(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	require.Len(t, parts, 3, "token should be a 3-part JWS")
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	require.NoError(t, err)
	var header map[string]any
	require.NoError(t, json.Unmarshal(headerBytes, &header))
	kid, ok := header["kid"].(string)
	require.True(t, ok, "kid header should be a string")
	require.NotEmpty(t, kid)
	return kid
}

// jwksFirstKID fetches /.well-known/jwks.json and returns the first key's kid.
func jwksFirstKID(t *testing.T, serverURL string) string {
	t.Helper()
	resp, err := http.Get(serverURL + JWKSEndpoint)
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)
	var jwks map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&jwks))
	keys, ok := jwks["keys"].([]any)
	require.True(t, ok)
	require.Len(t, keys, 1)
	kid, ok := keys[0].(map[string]any)["kid"].(string)
	require.True(t, ok)
	require.NotEmpty(t, kid)
	return kid
}

// TestRefreshTokenUsesCurrentSigningKid simulates a key rotation across a pod
// restart: an initial server mints tokens using key A and persists the refresh
// token session in storage; a second server is then constructed using the same
// storage but a different signing key (B), and a refresh_token grant is made
// against it. The resulting access token's "kid" header MUST advertise key B's
// kid so downstream JWKS-based verifiers (e.g. Grafana) can verify the token.
//
// Regression for: after a cert-manager-managed signing key rotation, refresh
// tokens minted by the old pod were causing the new pod to emit JWTs with the
// old kid in the header (restored from fosite session storage), even though the
// JWKS endpoint now publishes only the new key. Grafana then rejected the token
// with "failed to verify JWT: no keys found".
func TestRefreshTokenUsesCurrentSigningKid(t *testing.T) {
	// Shared storage across the two "pods"
	tmpDir, err := os.MkdirTemp("", "idp_test_rotation_*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	dbPath := filepath.Join(tmpDir, "test.db")
	repo, err := repository.NewKVSRepository(dbPath, "test")
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	// --- "Pod A" with signing key A: register client, mint initial tokens.
	keyA, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	serverA := setupTestServerWithKey(t, repo, keyA)

	kidA := jwksFirstKID(t, serverA.URL)

	regResp := registerTestClient(t, serverA.URL)

	config := &oauth2.Config{
		ClientID:     regResp.ClientID,
		ClientSecret: regResp.ClientSecret,
		RedirectURL:  "http://localhost:8080/callback",
		Scopes:       []string{},
		Endpoint: oauth2.Endpoint{
			AuthURL:  serverA.URL + AuthorizationEndpoint,
			TokenURL: serverA.URL + TokenEndpoint,
		},
	}

	callbackURL := testAuthFlowWithURL(t, serverA.URL, config.AuthCodeURL("test-state", oauth2.AccessTypeOffline))
	code := callbackURL.Query().Get("code")
	require.NotEmpty(t, code)

	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", code)
	tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
	tokenReq.Set("client_id", regResp.ClientID)
	tokenReq.Set("client_secret", regResp.ClientSecret)

	tokenResp, err := http.PostForm(serverA.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult map[string]any
	require.NoError(t, json.NewDecoder(tokenResp.Body).Decode(&tokenResult))

	initialAccess, _ := tokenResult["access_token"].(string)
	require.NotEmpty(t, initialAccess)
	refreshToken, _ := tokenResult["refresh_token"].(string)
	require.NotEmpty(t, refreshToken)

	require.Equal(t, kidA, jwtKID(t, initialAccess),
		"initial access token should advertise key A's kid")

	// --- "Pod B" with rotated signing key B: same shared storage.
	keyB, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	require.NotEqual(t, keyA.PublicKey.N.String(), keyB.PublicKey.N.String(),
		"test setup error: regenerated key matches the previous one")
	serverA.Close()
	serverB := setupTestServerWithKey(t, repo, keyB)

	kidB := jwksFirstKID(t, serverB.URL)
	require.NotEqual(t, kidA, kidB, "JWKS should publish the rotated key's kid")

	// --- Perform refresh_token grant against the rotated pod.
	refreshReq := url.Values{}
	refreshReq.Set("grant_type", "refresh_token")
	refreshReq.Set("refresh_token", refreshToken)
	refreshReq.Set("client_id", regResp.ClientID)
	refreshReq.Set("client_secret", regResp.ClientSecret)

	refreshResp, err := http.PostForm(serverB.URL+TokenEndpoint, refreshReq)
	require.NoError(t, err)
	defer refreshResp.Body.Close()
	require.Equal(t, http.StatusOK, refreshResp.StatusCode)

	var refreshResult map[string]any
	require.NoError(t, json.NewDecoder(refreshResp.Body).Decode(&refreshResult))

	refreshedAccess, _ := refreshResult["access_token"].(string)
	require.NotEmpty(t, refreshedAccess)
	require.NotEqual(t, initialAccess, refreshedAccess,
		"refresh should produce a new access token")

	// --- The new access token MUST be tagged with key B's kid, NOT the kid
	// that was persisted in the refresh-token session at issuance time.
	require.Equal(t, kidB, jwtKID(t, refreshedAccess),
		"refreshed access token must advertise the CURRENT signing key's kid (rotated key B), not the stored kid from key A")
}

func TestAccessTokenPreservesUserIdentity(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

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

	callbackURL := testAuthFlowWithURL(t, server.URL, config.AuthCodeURL("test-state"))
	code := callbackURL.Query().Get("code")

	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", code)
	tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
	tokenReq.Set("client_id", regResp.ClientID)
	tokenReq.Set("client_secret", regResp.ClientSecret)

	tokenResp, err := http.PostForm(server.URL+TokenEndpoint, tokenReq)
	require.NoError(t, err)
	defer tokenResp.Body.Close()
	require.Equal(t, http.StatusOK, tokenResp.StatusCode)

	var tokenResult map[string]any
	err = json.NewDecoder(tokenResp.Body).Decode(&tokenResult)
	require.NoError(t, err)

	accessToken := tokenResult["access_token"].(string)

	// Decode JWT payload
	parts := strings.Split(accessToken, ".")
	require.Len(t, parts, 3)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	err = json.Unmarshal(payload, &claims)
	require.NoError(t, err)

	// Verify sub claim is preserved
	sub, ok := claims["sub"].(string)
	require.True(t, ok, "sub claim should be present")
	require.Equal(t, "test-user@example.com", sub)

	// Verify userinfo claim is preserved
	userinfo, ok := claims["userinfo"].(map[string]any)
	require.True(t, ok, "userinfo claim should be present")
	require.Equal(t, "test-user@example.com", userinfo["email"])
	require.Equal(t, "Test User", userinfo["name"])
}
