package auth

import (
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
)

func setupTestRouter(authRouter *AuthRouter) *gin.Engine {
	router := gin.New()

	// Setup session middleware
	store := memstore.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("session", store))

	// Setup dummy protected route
	router.GET("/", authRouter.RequireAuth(), func(c *gin.Context) {
		c.String(http.StatusOK, "authenticated")
	})

	// Setup authentication routes
	authRouter.SetupRoutes(router)

	return router
}

func setupClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

func TestFilterUserInfo(t *testing.T) {
	t.Run("filters to specified keys", func(t *testing.T) {
		info := map[string]any{
			"email":              "user@example.com",
			"preferred_username": "user",
			"groups":             []any{"admin", "dev"},
			"realm_access":       map[string]any{"roles": []any{"offline_access"}},
		}
		filtered := filterUserInfo(info, []string{"email", "preferred_username"})
		require.Equal(t, map[string]any{
			"email":              "user@example.com",
			"preferred_username": "user",
		}, filtered)
	})

	t.Run("missing keys are skipped", func(t *testing.T) {
		info := map[string]any{"email": "user@example.com"}
		filtered := filterUserInfo(info, []string{"email", "name"})
		require.Equal(t, map[string]any{"email": "user@example.com"}, filtered)
	})

	t.Run("empty keys returns empty map", func(t *testing.T) {
		info := map[string]any{"email": "user@example.com"}
		filtered := filterUserInfo(info, []string{})
		require.Empty(t, filtered)
	})

	t.Run("nil input returns empty map", func(t *testing.T) {
		filtered := filterUserInfo(nil, []string{"email"})
		require.Empty(t, filtered)
	})
}

func TestUserInfoFilteringInOAuthFlow(t *testing.T) {
	t.Run("session stores only filtered userinfo fields", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		fullUserInfo := map[string]any{
			"email":              "user@example.com",
			"preferred_username": "user",
			"groups":             []any{"admin", "developers", "platform-team"},
			"realm_access":       map[string]any{"roles": []any{"offline_access", "uma_authorization"}},
			"resource_access":    map[string]any{"account": map[string]any{"roles": []any{"view-profile"}}},
		}

		mockToken := &oauth2.Token{AccessToken: "test-token"}
		mockProvider := NewMockProvider(ctrl)
		mockProvider.EXPECT().Name().Return("test").AnyTimes()
		mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
		mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()
		mockProvider.EXPECT().AuthCodeURL(gomock.Any()).Return("https://example.com/oauth", nil)
		mockProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).Return(mockToken, nil)
		mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(true, "user@example.com", fullUserInfo, nil)

		authRouter, err := NewAuthRouter(nil, false, []string{"email", "preferred_username"}, mockProvider)
		require.NoError(t, err)

		// Add a route that reads back the session to verify stored userinfo
		var storedUserInfo string
		router := gin.New()
		store := memstore.NewStore([]byte("test-secret"))
		router.Use(sessions.Sessions("session", store))
		authRouter.SetupRoutes(router)
		router.GET("/check-session", func(c *gin.Context) {
			session := sessions.Default(c)
			if v, ok := session.Get(SessionKeyUserInfo).(string); ok {
				storedUserInfo = v
			}
			c.String(http.StatusOK, "ok")
		})

		server := httptest.NewServer(router)
		defer server.Close()
		client := setupClient()

		// Start auth flow to set oauth state
		resp, err := client.Get(server.URL + "/.auth/test")
		require.NoError(t, err)
		resp.Body.Close()

		// Complete callback
		resp, err = client.Get(server.URL + "/.auth/test/callback")
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusFound, resp.StatusCode)

		// Read back session
		resp, err = client.Get(server.URL + "/check-session")
		require.NoError(t, err)
		resp.Body.Close()

		var parsed map[string]any
		require.NoError(t, json.Unmarshal([]byte(storedUserInfo), &parsed))
		require.Equal(t, "user@example.com", parsed["email"])
		require.Equal(t, "user", parsed["preferred_username"])
		require.NotContains(t, parsed, "groups")
		require.NotContains(t, parsed, "realm_access")
		require.NotContains(t, parsed, "resource_access")
	})

	t.Run("nil filter stores full userinfo", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		fullUserInfo := map[string]any{
			"email":  "user@example.com",
			"groups": []any{"admin"},
		}

		mockToken := &oauth2.Token{AccessToken: "test-token"}
		mockProvider := NewMockProvider(ctrl)
		mockProvider.EXPECT().Name().Return("test").AnyTimes()
		mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
		mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()
		mockProvider.EXPECT().AuthCodeURL(gomock.Any()).Return("https://example.com/oauth", nil)
		mockProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).Return(mockToken, nil)
		mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(true, "user@example.com", fullUserInfo, nil)

		authRouter, err := NewAuthRouter(nil, false, nil, mockProvider)
		require.NoError(t, err)

		var storedUserInfo string
		router := gin.New()
		store := memstore.NewStore([]byte("test-secret"))
		router.Use(sessions.Sessions("session", store))
		authRouter.SetupRoutes(router)
		router.GET("/check-session", func(c *gin.Context) {
			session := sessions.Default(c)
			if v, ok := session.Get(SessionKeyUserInfo).(string); ok {
				storedUserInfo = v
			}
			c.String(http.StatusOK, "ok")
		})

		server := httptest.NewServer(router)
		defer server.Close()
		client := setupClient()

		resp, err := client.Get(server.URL + "/.auth/test")
		require.NoError(t, err)
		resp.Body.Close()

		resp, err = client.Get(server.URL + "/.auth/test/callback")
		require.NoError(t, err)
		resp.Body.Close()

		resp, err = client.Get(server.URL + "/check-session")
		require.NoError(t, err)
		resp.Body.Close()

		var parsed map[string]any
		require.NoError(t, json.Unmarshal([]byte(storedUserInfo), &parsed))
		require.Contains(t, parsed, "email")
		require.Contains(t, parsed, "groups")
	})
}

func TestAuthenticationFlow(t *testing.T) {
	t.Run("Unauthenticated access should redirect to login", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Create mock provider
		mockProvider := NewMockProvider(ctrl)
		mockProvider.EXPECT().Name().Return("test").AnyTimes()
		mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
		mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()

		// Create AuthRouter (auto-select enabled by default)
		authRouter, err := NewAuthRouter(nil, false, nil, mockProvider)
		require.NoError(t, err)

		router := setupTestRouter(authRouter)
		server := httptest.NewServer(router)
		defer server.Close()

		client := setupClient()

		resp, err := client.Get(server.URL + "/")
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusFound, resp.StatusCode)

		location := resp.Header.Get("Location")
		require.Equal(t, LoginEndpoint, location)
	})

	t.Run("OAuth authentication flow", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Create mock provider
		mockToken := &oauth2.Token{AccessToken: "test-token"}
		mockProvider := NewMockProvider(ctrl)
		mockProvider.EXPECT().Name().Return("test").AnyTimes()
		mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
		mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()
		mockProvider.EXPECT().AuthCodeURL(gomock.Any()).Return("https://example.com/oauth", nil)
		mockProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).Return(mockToken, nil)
		mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(true, "authorized_user", map[string]any{"email": "authorized_user@example.com"}, nil)

		// Create AuthRouter
		authRouter, err := NewAuthRouter(nil, false, nil, mockProvider)
		require.NoError(t, err)

		router := setupTestRouter(authRouter)
		server := httptest.NewServer(router)
		defer server.Close()

		client := setupClient()

		// Step 1: Access unauthenticated route first to set redirectURL in session
		resp, err := client.Get(server.URL + "/")
		require.NoError(t, err)
		resp.Body.Close()

		// Verify redirect to login page
		require.Equal(t, http.StatusFound, resp.StatusCode)

		// Step 2: Start authentication
		resp, err = client.Get(server.URL + "/.auth/test")
		require.NoError(t, err)
		resp.Body.Close()

		require.Equal(t, http.StatusFound, resp.StatusCode)

		location := resp.Header.Get("Location")
		require.Equal(t, "https://example.com/oauth", location)

		// Step 3: Handle callback
		resp, err = client.Get(server.URL + "/.auth/test/callback")
		require.NoError(t, err)
		resp.Body.Close()

		require.Equal(t, http.StatusFound, resp.StatusCode)
		location = resp.Header.Get("Location")
		require.Equal(t, "/", location)

		// Step 4: Access after authentication
		resp, err = client.Get(server.URL + "/")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Unauthorized user should be blocked", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		// Create mock provider
		mockToken := &oauth2.Token{AccessToken: "test-token"}
		mockProvider := NewMockProvider(ctrl)
		mockProvider.EXPECT().Name().Return("test").AnyTimes()
		mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
		mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()
		mockProvider.EXPECT().AuthCodeURL(gomock.Any()).Return("https://example.com/oauth", nil)
		mockProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).Return(mockToken, nil)
		mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(false, "unauthorized_user", map[string]any{"email": "unauthorized_user@example.com"}, nil)

		// Create AuthRouter
		authRouter, err := NewAuthRouter(nil, false, nil, mockProvider)
		require.NoError(t, err)

		router := setupTestRouter(authRouter)
		server := httptest.NewServer(router)
		defer server.Close()

		client := setupClient()

		// Step 1: Access unauthenticated route first
		resp, err := client.Get(server.URL + "/")
		require.NoError(t, err)
		resp.Body.Close()

		// Step 2: Start authentication
		resp, err = client.Get(server.URL + "/.auth/test")
		require.NoError(t, err)
		resp.Body.Close()

		// Step 3: Complete authentication
		resp, err = client.Get(server.URL + "/.auth/test/callback")
		require.NoError(t, err)
		resp.Body.Close()

		require.Equal(t, http.StatusForbidden, resp.StatusCode)

		// Step 4: Test access when authorization fails
		resp, err = client.Get(server.URL + "/")
		if err != nil {
			t.Fatalf("Request failed: %v", err)
		}
		defer resp.Body.Close()

		require.Equal(t, http.StatusFound, resp.StatusCode)
		location := resp.Header.Get("Location")
		require.Equal(t, "/.auth/login", location)
	})
}

func TestLoginAutoRedirect(t *testing.T) {
	t.Run("Auto-redirects when single provider and no password", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockProvider := NewMockProvider(ctrl)
		mockProvider.EXPECT().Name().Return("test").AnyTimes()
		mockProvider.EXPECT().Type().Return("test").AnyTimes()
		mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
		mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()

		authRouter, err := NewAuthRouter(nil, false, nil, mockProvider)
		require.NoError(t, err)

		router := gin.New()
		store := memstore.NewStore([]byte("test-secret"))
		router.Use(sessions.Sessions("session", store))
		authRouter.SetupRoutes(router)

		server := httptest.NewServer(router)
		defer server.Close()

		client := setupClient()
		resp, err := client.Get(server.URL + LoginEndpoint)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusFound, resp.StatusCode)
		location := resp.Header.Get("Location")
		require.Equal(t, "/.auth/test", location)
	})

	t.Run("Does not redirect when disabled", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockProvider := NewMockProvider(ctrl)
		mockProvider.EXPECT().Name().Return("test").AnyTimes()
		mockProvider.EXPECT().Type().Return("test").AnyTimes()
		mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
		mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()

		authRouter, err := NewAuthRouter(nil, true, nil, mockProvider)
		require.NoError(t, err)

		router := gin.New()
		store := memstore.NewStore([]byte("test-secret"))
		router.Use(sessions.Sessions("session", store))
		authRouter.SetupRoutes(router)

		server := httptest.NewServer(router)
		defer server.Close()

		client := setupClient()
		resp, err := client.Get(server.URL + LoginEndpoint)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("Does not redirect when password configured", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockProvider := NewMockProvider(ctrl)
		mockProvider.EXPECT().Name().Return("test").AnyTimes()
		mockProvider.EXPECT().Type().Return("test").AnyTimes()
		mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
		mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()

		// Non-empty passwordHash slice disables auto-select
		authRouter, err := NewAuthRouter([]string{"dummy"}, false, nil, mockProvider)
		require.NoError(t, err)

		router := gin.New()
		store := memstore.NewStore([]byte("test-secret"))
		router.Use(sessions.Sessions("session", store))
		authRouter.SetupRoutes(router)

		server := httptest.NewServer(router)
		defer server.Close()

		client := setupClient()
		resp, err := client.Get(server.URL + LoginEndpoint)
		require.NoError(t, err)
		defer resp.Body.Close()

		require.Equal(t, http.StatusOK, resp.StatusCode)
	})
}
