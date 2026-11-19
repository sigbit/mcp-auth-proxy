package auth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
)

// The session records which provider authenticated the user, so the IdP can
// put it in the access token.
func TestSessionRecordsProvider(t *testing.T) {
	gin.SetMode(gin.TestMode)

	newServer := func(t *testing.T, authRouter *AuthRouter, storedProvider *string) *httptest.Server {
		router := gin.New()
		router.Use(sessions.Sessions("session", memstore.NewStore([]byte("test-secret"))))
		authRouter.SetupRoutes(router)
		router.GET("/check-session", func(c *gin.Context) {
			if v, ok := sessions.Default(c).Get(SessionKeyProvider).(string); ok {
				*storedProvider = v
			}
			c.String(http.StatusOK, "ok")
		})
		server := httptest.NewServer(router)
		t.Cleanup(server.Close)
		return server
	}

	t.Run("OAuth provider", func(t *testing.T) {
		ctrl := gomock.NewController(t)
		mockToken := &oauth2.Token{AccessToken: "test-token"}
		mockProvider := NewMockProvider(ctrl)
		mockProvider.EXPECT().Name().Return("Test").AnyTimes()
		mockProvider.EXPECT().Type().Return("test").AnyTimes()
		mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
		mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()
		var state string
		mockProvider.EXPECT().AuthCodeURL(gomock.Any()).DoAndReturn(func(s string) (string, error) {
			state = s
			return "https://example.com/oauth", nil
		})
		mockProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).Return(mockToken, nil)
		mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(true, "user@example.com", nil, nil)

		authRouter, err := NewAuthRouter(zap.NewNop(), nil, false, nil, NewFlowCookies([]byte("test-secret"), false), mockProvider)
		require.NoError(t, err)
		var storedProvider string
		server := newServer(t, authRouter, &storedProvider)
		client := setupClient()

		resp, err := client.Get(server.URL + "/.auth/test")
		require.NoError(t, err)
		resp.Body.Close()
		resp, err = client.Get(server.URL + "/.auth/test/callback?state=" + state)
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusFound, resp.StatusCode)

		resp, err = client.Get(server.URL + "/check-session")
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, "test", storedProvider)
	})

	t.Run("password", func(t *testing.T) {
		hash, err := bcrypt.GenerateFromPassword([]byte("secret"), bcrypt.MinCost)
		require.NoError(t, err)
		authRouter, err := NewAuthRouter(zap.NewNop(), []string{string(hash)}, false, nil, NewFlowCookies([]byte("test-secret"), false))
		require.NoError(t, err)
		var storedProvider string
		server := newServer(t, authRouter, &storedProvider)
		client := setupClient()

		resp, err := client.PostForm(server.URL+LoginEndpoint, url.Values{"password": {"secret"}})
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, http.StatusFound, resp.StatusCode)

		resp, err = client.Get(server.URL + "/check-session")
		require.NoError(t, err)
		resp.Body.Close()
		require.Equal(t, PasswordProvider, storedProvider)
	})
}
