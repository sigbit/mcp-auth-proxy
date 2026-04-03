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
	"golang.org/x/crypto/bcrypt"
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
		authRouter, err := NewAuthRouter(nil, false, mockProvider)
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
		mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(true, "authorized_user", nil)

		// Create AuthRouter
		authRouter, err := NewAuthRouter(nil, false, mockProvider)
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
		mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(false, "unauthorized_user", nil)

		// Create AuthRouter
		authRouter, err := NewAuthRouter(nil, false, mockProvider)
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

func TestAuthenticationFlow_StoresUserID(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockToken := &oauth2.Token{AccessToken: "test-token"}
	mockProvider := NewMockProvider(ctrl)
	mockProvider.EXPECT().Name().Return("test").AnyTimes()
	mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
	mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()
	mockProvider.EXPECT().AuthCodeURL(gomock.Any()).Return("https://example.com/oauth", nil)
	mockProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).Return(mockToken, nil)
	mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(true, "jane@example.com", nil)

	authRouter, err := NewAuthRouter(nil, false, mockProvider)
	require.NoError(t, err)

	router := gin.New()
	store := memstore.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("session", store))
	authRouter.SetupRoutes(router)
	router.GET("/check-session", authRouter.RequireAuth(), func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get(SessionKeyUserID)
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	server := httptest.NewServer(router)
	defer server.Close()
	client := setupClient()

	// Step 1: Trigger redirect to set session
	resp, err := client.Get(server.URL + "/check-session")
	require.NoError(t, err)
	resp.Body.Close()

	// Step 2: Start auth
	resp, err = client.Get(server.URL + "/.auth/test")
	require.NoError(t, err)
	resp.Body.Close()

	// Step 3: Callback
	resp, err = client.Get(server.URL + "/.auth/test/callback")
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Step 4: Verify session contains user_id
	resp, err = client.Get(server.URL + "/check-session")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	err = json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	require.Equal(t, "jane@example.com", body["user_id"])
}

func TestPasswordLogin_StoresPasswordUserID(t *testing.T) {
	// Generate a bcrypt hash for "testpass"
	hash, err := bcrypt.GenerateFromPassword([]byte("testpass"), bcrypt.DefaultCost)
	require.NoError(t, err)

	authRouter, err := NewAuthRouter([]string{string(hash)}, false)
	require.NoError(t, err)

	router := gin.New()
	store := memstore.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("session", store))
	authRouter.SetupRoutes(router)
	router.GET("/check-session", authRouter.RequireAuth(), func(c *gin.Context) {
		session := sessions.Default(c)
		userID := session.Get(SessionKeyUserID)
		c.JSON(http.StatusOK, gin.H{"user_id": userID})
	})

	server := httptest.NewServer(router)
	defer server.Close()
	client := setupClient()

	// Step 1: POST login with correct password
	resp, err := client.PostForm(server.URL+LoginEndpoint, map[string][]string{
		"password": {"testpass"},
	})
	require.NoError(t, err)
	resp.Body.Close()
	require.Equal(t, http.StatusFound, resp.StatusCode)

	// Step 2: Verify session contains PasswordUserID
	resp, err = client.Get(server.URL + "/check-session")
	require.NoError(t, err)
	defer resp.Body.Close()
	require.Equal(t, http.StatusOK, resp.StatusCode)

	var body map[string]any
	err = json.NewDecoder(resp.Body).Decode(&body)
	require.NoError(t, err)
	require.Equal(t, PasswordUserID, body["user_id"])
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

		authRouter, err := NewAuthRouter(nil, false, mockProvider)
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

		authRouter, err := NewAuthRouter(nil, true, mockProvider)
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
		authRouter, err := NewAuthRouter([]string{"dummy"}, false, mockProvider)
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
