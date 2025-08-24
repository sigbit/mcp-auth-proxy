package auth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

const (
	TestOIDCClientID     = "test-oidc-client-id"
	TestOIDCClientSecret = "test-oidc-client-secret"
	TestOIDCExternalURL  = "http://localhost:8080"
	TestOIDCProviderName = "TestOIDC"
	TestOIDCUserIDField  = "/sub"
)

func setupOIDCTest(allowedUsers []string, userIDField string) (Provider, gin.IRoutes, gin.IRoutes, *httptest.Server) {
	// Setup OIDC configuration server
	configServer := gin.New()
	configServer.GET("/.well-known/openid_configuration", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"authorization_endpoint": "http://localhost:8080/auth",
			"token_endpoint":         "http://localhost:8080/token",
			"userinfo_endpoint":      "http://localhost:8080/userinfo",
		})
	})
	tsConfig := httptest.NewServer(configServer)

	if userIDField == "" {
		userIDField = TestOIDCUserIDField
	}

	p, err := NewOIDCProvider(
		tsConfig.URL+"/.well-known/openid_configuration",
		[]string{"openid", "profile"},
		userIDField,
		TestOIDCProviderName,
		TestOIDCExternalURL,
		TestOIDCClientID,
		TestOIDCClientSecret,
		allowedUsers,
	)
	if err != nil {
		panic(err)
	}

	// Setup OAuth2 token endpoint
	oauth := gin.New()
	oauth.POST("/token", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"access_token": "test-access-token",
			"token_type":   "Bearer",
		})
	})
	tsOAuth := httptest.NewServer(oauth)

	// Setup userinfo endpoint
	userinfo := gin.New()
	tsUserinfo := httptest.NewServer(userinfo)

	// Override endpoints in provider
	op := p.(*oidcProvider)
	op.oauth2.Endpoint = oauth2.Endpoint{
		AuthURL:  tsOAuth.URL + "/auth",
		TokenURL: tsOAuth.URL + "/token",
	}
	op.userInfoURL = tsUserinfo.URL + "/userinfo"

	return p, oauth, userinfo, tsConfig
}

func TestOIDCProvider(t *testing.T) {
	p, _, _, tsConfig := setupOIDCTest([]string{}, "")
	defer tsConfig.Close()

	require.Equal(t, p.Name(), TestOIDCProviderName)
	require.Equal(t, p.Type(), "oidc")
	require.Equal(t, p.RedirectURL(), OIDCCallbackEndpoint)
	require.Equal(t, p.AuthURL(), OIDCAuthEndpoint)

	// Check AuthCodeURL
	authCodeURL, err := p.AuthCodeURL("test-state")
	require.NoError(t, err)
	require.NotEmpty(t, authCodeURL)
	authCodeURLObj, err := url.Parse(authCodeURL)
	require.NoError(t, err)
	require.Equal(t, authCodeURLObj.Query().Get("client_id"), TestOIDCClientID)
	require.Equal(t, authCodeURLObj.Query().Get("redirect_uri"), TestOIDCExternalURL+"/.auth/oidc/callback")
	require.Equal(t, authCodeURLObj.Query().Get("response_type"), "code")
	require.Equal(t, authCodeURLObj.Query().Get("state"), "test-state")
	require.Contains(t, authCodeURLObj.Query().Get("scope"), "openid")

	// Check Exchange
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	req, _ := http.NewRequest("GET", "/?state=test-state&code=test-code", nil)
	c.Request = req
	_, err = p.Exchange(c, "invalid-state")
	require.Error(t, err)
	token, err := p.Exchange(c, "test-state")
	require.NoError(t, err)
	require.NotNil(t, token)
	require.Equal(t, token.AccessToken, "test-access-token")
}

func TestOIDCProviderAuthorization(t *testing.T) {
	tc := []struct {
		name         string
		allowedUsers []string
		userIDField  string
		userResp     string
		expect       bool
	}{
		{
			name:         "allow all users",
			allowedUsers: []string{},
			userIDField:  "/sub",
			userResp:     `{"sub": "user1", "name": "Test User"}`,
			expect:       true,
		},
		{
			name:         "allow single user",
			allowedUsers: []string{"user1", "user2"},
			userIDField:  "/sub",
			userResp:     `{"sub": "user1", "name": "Test User"}`,
			expect:       true,
		},
		{
			name:         "deny single user",
			allowedUsers: []string{"user1"},
			userIDField:  "/sub",
			userResp:     `{"sub": "user2", "name": "Test User"}`,
			expect:       false,
		},
		{
			name:         "custom user ID field",
			allowedUsers: []string{"test@example.com"},
			userIDField:  "/email",
			userResp:     `{"sub": "user1", "email": "test@example.com", "name": "Test User"}`,
			expect:       true,
		},
		{
			name:         "nested user ID field",
			allowedUsers: []string{"user1"},
			userIDField:  "/profile/username",
			userResp:     `{"sub": "123", "profile": {"username": "user1", "display_name": "Test User"}}`,
			expect:       true,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			p, _, userinfo, tsConfig := setupOIDCTest(tt.allowedUsers, tt.userIDField)
			defer tsConfig.Close()

			userinfo.GET("/userinfo", func(c *gin.Context) {
				c.Data(http.StatusOK, "application/json", []byte(tt.userResp))
			})

			// Call the Authorization method
			ok, _, err := p.Authorization(context.Background(), &oauth2.Token{AccessToken: "test-access-token"})
			require.NoError(t, err)
			require.Equal(t, tt.expect, ok)
		})
	}
}

func TestOIDCProviderErrors(t *testing.T) {
	t.Run("invalid configuration URL", func(t *testing.T) {
		_, err := NewOIDCProvider(
			"http://invalid-url/.well-known/openid_configuration",
			[]string{"openid"},
			"/sub",
			"TestOIDC",
			TestOIDCExternalURL,
			TestOIDCClientID,
			TestOIDCClientSecret,
			[]string{},
		)
		require.Error(t, err)
	})

	t.Run("invalid JSON in configuration", func(t *testing.T) {
		configServer := gin.New()
		configServer.GET("/.well-known/openid_configuration", func(c *gin.Context) {
			c.String(http.StatusOK, "invalid json")
		})
		tsConfig := httptest.NewServer(configServer)
		defer tsConfig.Close()

		_, err := NewOIDCProvider(
			tsConfig.URL+"/.well-known/openid_configuration",
			[]string{"openid"},
			"/sub",
			"TestOIDC",
			TestOIDCExternalURL,
			TestOIDCClientID,
			TestOIDCClientSecret,
			[]string{},
		)
		require.Error(t, err)
	})

	t.Run("missing user ID field", func(t *testing.T) {
		p, _, userinfo, tsConfig := setupOIDCTest([]string{}, "/missing_field")
		defer tsConfig.Close()

		userinfo.GET("/userinfo", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"sub": "user1"})
		})

		ok, _, err := p.Authorization(context.Background(), &oauth2.Token{AccessToken: "test-access-token"})
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("non-string user ID field", func(t *testing.T) {
		p, _, userinfo, tsConfig := setupOIDCTest([]string{}, "/sub")
		defer tsConfig.Close()

		userinfo.GET("/userinfo", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"sub": 12345})
		})

		ok, _, err := p.Authorization(context.Background(), &oauth2.Token{AccessToken: "test-access-token"})
		require.Error(t, err)
		require.False(t, ok)
	})

	t.Run("userinfo endpoint error", func(t *testing.T) {
		p, _, userinfo, tsConfig := setupOIDCTest([]string{}, "/sub")
		defer tsConfig.Close()

		userinfo.GET("/userinfo", func(c *gin.Context) {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "server error"})
		})

		ok, _, err := p.Authorization(context.Background(), &oauth2.Token{AccessToken: "test-access-token"})
		require.Error(t, err)
		require.False(t, ok)
	})
}
