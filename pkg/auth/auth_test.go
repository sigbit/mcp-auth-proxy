package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
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
		// The identity provider echoes the state back on the callback.
		var state string
		mockProvider.EXPECT().AuthCodeURL(gomock.Any()).DoAndReturn(func(s string) (string, error) {
			state = s
			return "https://example.com/oauth", nil
		})
		mockProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).Return(mockToken, nil)
		mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(true, "user@example.com", fullUserInfo, nil)

		authRouter, err := NewAuthRouter(nil, false, []string{"email", "preferred_username"}, NewFlowCookies([]byte("test-secret"), false), mockProvider)
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
		resp, err = client.Get(server.URL + "/.auth/test/callback?state=" + state)
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
		// The identity provider echoes the state back on the callback.
		var state string
		mockProvider.EXPECT().AuthCodeURL(gomock.Any()).DoAndReturn(func(s string) (string, error) {
			state = s
			return "https://example.com/oauth", nil
		})
		mockProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).Return(mockToken, nil)
		mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(true, "user@example.com", fullUserInfo, nil)

		authRouter, err := NewAuthRouter(nil, false, nil, NewFlowCookies([]byte("test-secret"), false), mockProvider)
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

		resp, err = client.Get(server.URL + "/.auth/test/callback?state=" + state)
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
		authRouter, err := NewAuthRouter(nil, false, nil, NewFlowCookies([]byte("test-secret"), false), mockProvider)
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
		require.Equal(t, LoginEndpoint+"?rd=%2F", location)
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
		// The identity provider echoes the state back on the callback.
		var state string
		mockProvider.EXPECT().AuthCodeURL(gomock.Any()).DoAndReturn(func(s string) (string, error) {
			state = s
			return "https://example.com/oauth", nil
		})
		mockProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).Return(mockToken, nil)
		mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(true, "authorized_user", map[string]any{"email": "authorized_user@example.com"}, nil)

		// Create AuthRouter
		authRouter, err := NewAuthRouter(nil, false, nil, NewFlowCookies([]byte("test-secret"), false), mockProvider)
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
		resp, err = client.Get(server.URL + "/.auth/test/callback?state=" + state)
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
		// The identity provider echoes the state back on the callback.
		var state string
		mockProvider.EXPECT().AuthCodeURL(gomock.Any()).DoAndReturn(func(s string) (string, error) {
			state = s
			return "https://example.com/oauth", nil
		})
		mockProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).Return(mockToken, nil)
		mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(false, "unauthorized_user", map[string]any{"email": "unauthorized_user@example.com"}, nil)

		// Create AuthRouter
		authRouter, err := NewAuthRouter(nil, false, nil, NewFlowCookies([]byte("test-secret"), false), mockProvider)
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
		resp, err = client.Get(server.URL + "/.auth/test/callback?state=" + state)
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
		require.Equal(t, "/.auth/login?rd=%2F", location)
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

		authRouter, err := NewAuthRouter(nil, false, nil, NewFlowCookies([]byte("test-secret"), false), mockProvider)
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

		authRouter, err := NewAuthRouter(nil, true, nil, NewFlowCookies([]byte("test-secret"), false), mockProvider)
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
		authRouter, err := NewAuthRouter([]string{"dummy"}, false, nil, NewFlowCookies([]byte("test-secret"), false), mockProvider)
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

// fanOut sends every request with the cookies the jar holds right now, and
// only then applies each response's Set-Cookie to the jar, in order. That is
// what a browser does when a client opens many authorization flows at once:
// every request leaves before any response arrives, so they all carry the
// same cookie and the last response to land wins.
func fanOut(t *testing.T, jar http.CookieJar, rawURLs []string) []*http.Response {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	var reqs []*http.Request
	for _, raw := range rawURLs {
		req, err := http.NewRequest(http.MethodGet, raw, nil)
		require.NoError(t, err)
		for _, c := range jar.Cookies(req.URL) {
			req.AddCookie(c)
		}
		reqs = append(reqs, req)
	}
	var resps []*http.Response
	for _, req := range reqs {
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()
		resps = append(resps, resp)
	}
	for i, resp := range resps {
		jar.SetCookies(reqs[i].URL, resp.Cookies())
	}
	return resps
}

// Claude's desktop app starts the OAuth flow for every configured MCP server
// at the same moment, in one browser. With the flow state held in the one
// shared session cookie, each flow overwrote its siblings' state, and in
// production 15 of 16 callbacks failed with "invalid OAuth state"
// (2026-09-30). Every flow must complete, and each must land back on the
// page that started it rather than on whichever flow wrote last.
func TestConcurrentOAuthFlows(t *testing.T) {
	const flows = 16

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockToken := &oauth2.Token{AccessToken: "test-token"}
	mockProvider := NewMockProvider(ctrl)
	mockProvider.EXPECT().Name().Return("test").AnyTimes()
	mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
	mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()
	mockProvider.EXPECT().AuthCodeURL(gomock.Any()).DoAndReturn(func(state string) (string, error) {
		return "https://idp.example.com/authorize?state=" + state, nil
	}).AnyTimes()
	mockProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).DoAndReturn(func(c *gin.Context, state string) (*oauth2.Token, error) {
		if c.Query("state") != state {
			return nil, errors.New("invalid OAuth state")
		}
		return mockToken, nil
	}).AnyTimes()
	mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(true, "user@example.com", nil, nil).AnyTimes()

	authRouter, err := NewAuthRouter(nil, false, nil, NewFlowCookies([]byte("test-secret"), false), mockProvider)
	require.NoError(t, err)

	router := gin.New()
	router.Use(sessions.Sessions("session", memstore.NewStore([]byte("test-secret"))))
	router.GET("/protected/:n", authRouter.RequireAuth(), func(c *gin.Context) {
		c.String(http.StatusOK, "ok")
	})
	authRouter.SetupRoutes(router)
	server := httptest.NewServer(router)
	defer server.Close()

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)

	// Follow every flow in lockstep, one hop at a time, until each has left
	// for the identity provider.
	urls := make([]string, flows)
	for i := range urls {
		urls[i] = fmt.Sprintf("%s/protected/%d", server.URL, i)
	}
	for hop := 0; ; hop++ {
		require.Less(t, hop, 5, "flows never reached the identity provider")
		resps := fanOut(t, jar, urls)
		done := true
		for i, resp := range resps {
			require.Equal(t, http.StatusFound, resp.StatusCode)
			loc := resp.Header.Get("Location")
			if strings.HasPrefix(loc, "https://idp.example.com/") {
				urls[i] = loc
				continue
			}
			done = false
			urls[i] = server.URL + loc
		}
		if done {
			break
		}
	}

	// The identity provider sends each browser back to the callback.
	callbacks := make([]string, flows)
	for i, idpURL := range urls {
		u, err := url.Parse(idpURL)
		require.NoError(t, err)
		callbacks[i] = server.URL + "/.auth/test/callback?code=c&state=" + u.Query().Get("state")
	}
	for i, resp := range fanOut(t, jar, callbacks) {
		require.Equal(t, http.StatusFound, resp.StatusCode, "flow %d did not complete", i)
		require.Equal(t, fmt.Sprintf("/protected/%d", i), resp.Header.Get("Location"),
			"flow %d returned to the wrong page", i)
	}
}

// The return address rides through the login redirects as a parameter, so it
// must never be able to send the browser off-site.
func TestLoginRedirectStaysOnSite(t *testing.T) {
	for _, rd := range []string{
		"https://evil.example.com/",
		"//evil.example.com/",
		`/\evil.example.com/`,
		"evil",
		"javascript:alert(1)",
	} {
		t.Run(rd, func(t *testing.T) {
			require.Empty(t, safeRedirect(rd))
		})
	}
	for _, rd := range []string{"/", "/.idp/auth/abc", "/x?y=z"} {
		t.Run(rd, func(t *testing.T) {
			require.Equal(t, rd, safeRedirect(rd))
		})
	}
}
