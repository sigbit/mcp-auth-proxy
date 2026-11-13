package auth

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/memstore"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

// TestRequireAuthStopsUnauthenticatedRequests is a regression test for the
// login bypass reported in November 2026: RequireAuth redirected to the
// login page but did not abort the gin handler chain, so the protected
// handler still ran for unauthenticated requests.
func TestRequireAuthStopsUnauthenticatedRequests(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockProvider := NewMockProvider(ctrl)
	mockProvider.EXPECT().Name().Return("test").AnyTimes()
	mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
	mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()

	authRouter, err := NewAuthRouter(nil, false, nil, mockProvider)
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
		require.Equal(t, LoginEndpoint, resp.Header.Get("Location"), "%s: expected redirect to login", method)
		require.False(t, handlerRan, "%s: protected handler must not run for unauthenticated requests", method)
	}
}
