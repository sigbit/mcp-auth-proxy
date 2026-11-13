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
	return setupTestServerBackend(t, "kvs")
}

func setupTestServerBackend(t *testing.T, backend string) (*httptest.Server, repository.Repository, string) {
	// Create temp directory and repository
	tmpDir, err := os.MkdirTemp("", "idp_test_*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	dbPath := filepath.Join(tmpDir, "test.db")
	var repo repository.Repository
	if backend == "sqlite" {
		repo, err = repository.NewSQLRepository("sqlite", dbPath)
	} else {
		repo, err = repository.NewKVSRepository(dbPath, "test")
	}
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
	authRouter, err := auth.NewAuthRouter([]string{}, false, nil, auth.NewFlowCookies(secret[:], false))
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
	for _, backend := range []string{"kvs", "sqlite"} {
		t.Run(backend, func(t *testing.T) { testPrivateClient(t, backend) })
	}
}

func testPrivateClient(t *testing.T, backend string) {
	server, _, _ := setupTestServerBackend(t, backend)

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
	verifier := oauth2.GenerateVerifier()
	state := "test-state"
	authURL := config.AuthCodeURL(state, oauth2.AccessTypeOffline, oauth2.S256ChallengeOption(verifier))

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
	tokenReq.Set("code_verifier", verifier)

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

	newRefreshToken, ok := refreshResult["refresh_token"].(string)
	require.True(t, ok)
	require.NotEmpty(t, newRefreshToken)
	oldGrace := repository.RefreshTokenGracePeriod
	repository.RefreshTokenGracePeriod = 0
	defer func() { repository.RefreshTokenGracePeriod = oldGrace }()

	// Reuse of the rotated token revokes the replacement grant.
	reuseResp, err := http.PostForm(server.URL+TokenEndpoint, refreshReq)
	require.NoError(t, err)
	defer reuseResp.Body.Close()
	require.Equal(t, http.StatusBadRequest, reuseResp.StatusCode)
	var reuseResult map[string]any
	require.NoError(t, json.NewDecoder(reuseResp.Body).Decode(&reuseResult))
	require.Equal(t, "invalid_grant", reuseResult["error"])
	refreshReq.Set("refresh_token", newRefreshToken)
	replacementResp, err := http.PostForm(server.URL+TokenEndpoint, refreshReq)
	require.NoError(t, err)
	defer replacementResp.Body.Close()
	require.Equal(t, http.StatusBadRequest, replacementResp.StatusCode)
	var replacementResult map[string]any
	require.NoError(t, json.NewDecoder(replacementResp.Body).Decode(&replacementResult))
	require.Equal(t, "invalid_grant", replacementResult["error"])
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

	verifier := oauth2.GenerateVerifier()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// Build authorization URL manually WITHOUT a state parameter
	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&code_challenge=%s&code_challenge_method=S256",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"), challenge)

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
	tokenReq.Set("code_verifier", verifier)

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

	verifier := oauth2.GenerateVerifier()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// Build authorization URL with an empty state parameter
	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=&code_challenge=%s&code_challenge_method=S256",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"), challenge)

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
	tokenReq.Set("code_verifier", verifier)

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

	verifier := oauth2.GenerateVerifier()
	callbackURL := testAuthFlowWithURL(t, server.URL, config.AuthCodeURL("test-state", oauth2.S256ChallengeOption(verifier)))
	code := callbackURL.Query().Get("code")

	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", code)
	tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
	tokenReq.Set("client_id", regResp.ClientID)
	tokenReq.Set("client_secret", regResp.ClientSecret)
	tokenReq.Set("code_verifier", verifier)

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

	verifier := oauth2.GenerateVerifier()
	callbackURL := testAuthFlowWithURL(t, server.URL, config.AuthCodeURL("test-state", oauth2.S256ChallengeOption(verifier)))
	code := callbackURL.Query().Get("code")

	tokenReq := url.Values{}
	tokenReq.Set("grant_type", "authorization_code")
	tokenReq.Set("code", code)
	tokenReq.Set("redirect_uri", "http://localhost:8080/callback")
	tokenReq.Set("client_id", regResp.ClientID)
	tokenReq.Set("client_secret", regResp.ClientSecret)
	tokenReq.Set("code_verifier", verifier)

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

// Claude's desktop app opens one authorization request per configured MCP
// server at the same moment. Pending request IDs were kept as a list in the
// shared session cookie, so each response replaced the whole list and the
// browser kept only the last: in production 12 of 15 consent pages answered
// "invalid authorization session" (2026-09-30). Every request started in
// this browser must still be recognised.
func TestConcurrentAuthorizationRequests(t *testing.T) {
	const flows = 16

	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)
	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}

	// PKCE is enforced for registered clients, so every request carries
	// the same challenge; the per-flow state is what this test exercises.
	verifier := "concurrent-verifier-concurrent-verifier-1234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// Every request leaves before any response is applied, as in a browser.
	var reqs []*http.Request
	for i := 0; i < flows; i++ {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf(
			"%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=concurrent-state-%d&code_challenge=%s&code_challenge_method=S256",
			server.URL, AuthorizationEndpoint, regResp.ClientID,
			url.QueryEscape("http://localhost:8080/callback"), i, challenge), nil)
		require.NoError(t, err)
		for _, c := range jar.Cookies(req.URL) {
			req.AddCookie(c)
		}
		reqs = append(reqs, req)
	}
	var locations []string
	var cookies [][]*http.Cookie
	for _, req := range reqs {
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusFound, resp.StatusCode)
		locations = append(locations, resp.Header.Get("Location"))
		cookies = append(cookies, resp.Cookies())
	}
	for i, req := range reqs {
		jar.SetCookies(req.URL, cookies[i])
	}

	client.Jar = jar
	for i, loc := range locations {
		resp, err := client.Post(server.URL+loc, "application/x-www-form-urlencoded", nil)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusSeeOther, resp.StatusCode, "request %d was not recognised", i)
		callback, err := url.Parse(resp.Header.Get("Location"))
		require.NoError(t, err)
		require.Equal(t, fmt.Sprintf("concurrent-state-%d", i), callback.Query().Get("state"))
		require.NotEmpty(t, callback.Query().Get("code"))
	}
}
