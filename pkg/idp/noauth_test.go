package idp

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
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
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/repository"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// setupTestServerNoAuth is like setupTestServer but without the mock
// middleware that marks every session as authorized, so requests go
// through the real RequireAuth middleware.
func setupTestServerNoAuth(t *testing.T) *httptest.Server {
	tmpDir, err := os.MkdirTemp("", "idp_test_noauth_*")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	repo, err := repository.NewKVSRepository(filepath.Join(tmpDir, "test.db"), "test")
	require.NoError(t, err)
	t.Cleanup(func() { repo.Close() })

	keyMaterial := sha256.Sum256([]byte("test" + "_secret"))
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	store := cookie.NewStore(keyMaterial[:])
	router.Use(sessions.Sessions("test_session", store))

	authRouter, err := auth.NewAuthRouter([]string{}, false, nil, auth.NewFlowCookies(keyMaterial[:], false))
	require.NoError(t, err)

	logger, _ := zap.NewDevelopment()
	idpRouter, err := NewIDPRouter(repo, privKey, logger, "http://localhost:8080", keyMaterial[:], authRouter)
	require.NoError(t, err)
	idpRouter.SetupRoutes(router)

	server := httptest.NewServer(router)
	t.Cleanup(server.Close)
	return server
}

// TestAuthorizationReturnRequiresLogin is an end-to-end regression test
// verifying that the authorization return endpoints require a login:
// without one, requests redirect to the login page and no authorization
// code is delivered to the client's redirect URI.
func TestAuthorizationReturnRequiresLogin(t *testing.T) {
	server := setupTestServerNoAuth(t)

	jar, _ := cookiejar.New(nil)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Register a public client (open dynamic client registration).
	regBody, _ := json.Marshal(map[string]any{
		"redirect_uris":              []string{"http://127.0.0.1:9999/cb"},
		"token_endpoint_auth_method": "none",
		"grant_types":                []string{"authorization_code"},
		"response_types":             []string{"code"},
		"scope":                      "openid",
	})
	resp, err := client.Post(server.URL+RegistrationEndpoint, "application/json", bytes.NewReader(regBody))
	require.NoError(t, err)
	require.Equal(t, http.StatusCreated, resp.StatusCode)
	var reg map[string]any
	require.NoError(t, json.NewDecoder(resp.Body).Decode(&reg))
	resp.Body.Close()
	clientID, _ := reg["client_id"].(string)
	require.NotEmpty(t, clientID)

	// Start an authorization request; this stores the authorize request
	// ID in the session cookie without any login.
	verifier := "test-verifier-test-verifier-test-verifier-1234567890"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])
	authURL := server.URL + AuthorizationEndpoint + "?" + url.Values{
		"response_type":         {"code"},
		"client_id":             {clientID},
		"redirect_uri":          {"http://127.0.0.1:9999/cb"},
		"state":                 {"test-state"},
		"code_challenge":        {challenge},
		"code_challenge_method": {"S256"},
	}.Encode()
	resp, err = client.Get(authURL)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	returnPath := resp.Header.Get("Location")
	require.True(t, strings.HasPrefix(returnPath, "/.idp/auth/"), "unexpected redirect: %s", returnPath)

	// The consent form (GET) must redirect to the login page.
	resp, err = client.Get(server.URL + returnPath)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	// The login redirect carries the return address as a query parameter
	// so that concurrent flows cannot overwrite each other's.
	require.Equal(t, auth.LoginEndpoint+"?rd="+url.QueryEscape(returnPath), resp.Header.Get("Location"))

	// The code-issuing POST must redirect to the login page and must
	// not deliver an authorization code to the client's redirect URI.
	resp, err = client.Post(server.URL+returnPath, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)
	location := resp.Header.Get("Location")
	require.Equal(t, auth.LoginEndpoint+"?rd="+url.QueryEscape(returnPath), location)
	require.NotContains(t, location, "code=")
}
