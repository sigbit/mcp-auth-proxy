package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"go.uber.org/zap"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestRequireAuthStopsUnauthenticatedRequests verifies that RequireAuth
// stops unauthenticated requests: they receive a redirect to the login
// page and the protected handler never runs.
func TestRequireAuthStopsUnauthenticatedRequests(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockProvider := NewMockProvider(ctrl)
	mockProvider.EXPECT().Name().Return("test").AnyTimes()
	mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
	mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()

	authRouter, err := NewAuthRouter(zap.NewNop(), nil, false, nil, NewFlowCookies([]byte("test-secret"), false), mockProvider)
	require.NoError(t, err)

	router := gin.New()
	store := memstore.NewStore([]byte("test-secret"))
	router.Use(sessions.Sessions("session", store))

	handlerRan := false
	protected := func(c *gin.Context) {
		handlerRan = true
		c.String(http.StatusOK, "authenticated")
	}
	router.GET("/protected", authRouter.RequireAuth(), protected)
	router.POST("/protected", authRouter.RequireAuth(), protected)

	server := httptest.NewServer(router)
	defer server.Close()
	client := setupClient()

	for _, method := range []string{http.MethodGet, http.MethodPost} {
		handlerRan = false
		req, err := http.NewRequest(method, server.URL+"/protected", nil)
		require.NoError(t, err)
		resp, err := client.Do(req)
		require.NoError(t, err)
		resp.Body.Close()

		require.Equal(t, http.StatusFound, resp.StatusCode, "%s: expected redirect to login", method)
		// The return address travels as a query parameter on the login
		// redirect so concurrent flows cannot overwrite each other's.
		require.Equal(t, LoginEndpoint+"?rd=%2Fprotected", resp.Header.Get("Location"), "%s: expected redirect to login", method)
		require.False(t, handlerRan, "%s: protected handler must not run for unauthenticated requests", method)
	}
}
