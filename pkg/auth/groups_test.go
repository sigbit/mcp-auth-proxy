package auth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
	"golang.org/x/oauth2"
)

func TestGroupsFilter(t *testing.T) {
	info := func(groups any) map[string]any {
		return map[string]any{"email": "user@example.com", "groups": groups}
	}

	cases := []struct {
		name     string
		patterns []string
		in       map[string]any
		want     map[string]any
	}{
		{
			name:     "keeps matching groups only",
			patterns: []string{"team-*", "admins"},
			in:       info([]any{"team-a", "admins", "all-staff", "team-b", "admins2"}),
			want:     info([]any{"team-a", "admins", "team-b"}),
		},
		{
			name:     "no match yields an empty list, not a missing claim",
			patterns: []string{"team-*"},
			in:       info([]any{"all-staff"}),
			want:     info([]any{}),
		},
		{
			name:     "no patterns keeps everything",
			patterns: nil,
			in:       info([]any{"team-a", "all-staff"}),
			want:     info([]any{"team-a", "all-staff"}),
		},
		{
			name:     "empty patterns are ignored",
			patterns: []string{""},
			in:       info([]any{"team-a", "all-staff"}),
			want:     info([]any{"team-a", "all-staff"}),
		},
		{
			name:     "missing claim is left alone",
			patterns: []string{"team-*"},
			in:       map[string]any{"email": "user@example.com"},
			want:     map[string]any{"email": "user@example.com"},
		},
		{
			// A claim the filter cannot read must not become "no groups":
			// downstream that reads as a refusal, not as a filter mismatch.
			name:     "non-list claim is left alone",
			patterns: []string{"team-*"},
			in:       info("team-a all-staff"),
			want:     info("team-a all-staff"),
		},
		{
			name:     "non-string entries are kept",
			patterns: []string{"team-*"},
			in:       info([]any{"team-a", 42.0, "all-staff"}),
			want:     info([]any{"team-a", 42.0}),
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f, err := NewGroupsFilter(tc.patterns)
			require.NoError(t, err)
			require.Equal(t, tc.want, f.Apply(tc.in))
		})
	}

	t.Run("does not mutate its input", func(t *testing.T) {
		f, err := NewGroupsFilter([]string{"team-*"})
		require.NoError(t, err)
		in := info([]any{"team-a", "all-staff"})
		f.Apply(in)
		require.Equal(t, []any{"team-a", "all-staff"}, in["groups"])
	})

	t.Run("nil filter keeps everything", func(t *testing.T) {
		var f *GroupsFilter
		in := info([]any{"team-a", "all-staff"})
		require.Equal(t, in, f.Apply(in))
	})

	t.Run("invalid pattern is an error", func(t *testing.T) {
		_, err := NewGroupsFilter([]string{"team-["})
		require.Error(t, err)
	})
}

// The point of the filter: a provider returning ~90 groups pushed the
// session cookie past securecookie's 4096-byte limit and failed every login
// at the callback. Filtering must bring a large membership under that limit.
func TestGroupsFilterKeepsSessionUnderCookieLimit(t *testing.T) {
	// securecookie's default maximum encoded length.
	const cookieLimit = 4096

	groups := make([]any, 0, 95)
	for i := 0; i < 90; i++ {
		groups = append(groups, fmt.Sprintf("distribution-list-%02d", i))
	}
	groups = append(groups, "team-a", "team-b", "team-c", "admins", "ops")
	in := map[string]any{"email": "user@example.com", "groups": groups}

	before, err := json.Marshal(in)
	require.NoError(t, err)
	require.Greater(t, len(before), cookieLimit/2,
		"fixture must be large enough that encoding overhead pushes it past the limit")

	f, err := NewGroupsFilter([]string{"team-*", "admins", "ops"})
	require.NoError(t, err)
	out := f.Apply(in)
	require.Equal(t, []any{"team-a", "team-b", "team-c", "admins", "ops"}, out["groups"])

	after, err := json.Marshal(out)
	require.NoError(t, err)
	require.Less(t, len(after), 200)
}

// Drives a full login callback through the cookie-backed session store the
// proxy uses in production -- memstore has no size limit, so it cannot
// reproduce the failure. Without the filter the callback fails with
// securecookie's "the value is too long"; with it, the login completes and
// the session carries only the kept groups.
func TestGroupsFilterInOAuthCallback(t *testing.T) {
	groups := make([]any, 0, 95)
	for i := 0; i < 90; i++ {
		groups = append(groups, fmt.Sprintf("Department Distribution List %02d", i))
	}
	groups = append(groups, "team-a", "team-b", "admins")
	fullUserInfo := map[string]any{"email": "user@example.com", "groups": groups}

	run := func(t *testing.T, filter *GroupsFilter) (*http.Response, string) {
		ctrl := gomock.NewController(t)
		defer ctrl.Finish()

		mockToken := &oauth2.Token{AccessToken: "test-token"}
		mockProvider := NewMockProvider(ctrl)
		mockProvider.EXPECT().Name().Return("test").AnyTimes()
		mockProvider.EXPECT().AuthURL().Return("/.auth/test").AnyTimes()
		mockProvider.EXPECT().RedirectURL().Return("/.auth/test/callback").AnyTimes()
		var state string
		mockProvider.EXPECT().AuthCodeURL(gomock.Any()).DoAndReturn(func(s string) (string, error) {
			state = s
			return "https://example.com/oauth", nil
		})
		mockProvider.EXPECT().Exchange(gomock.Any(), gomock.Any()).Return(mockToken, nil)
		mockProvider.EXPECT().Authorization(gomock.Any(), mockToken).Return(true, "user@example.com", fullUserInfo, nil)

		authRouter, err := NewAuthRouter(nil, false, []string{"email", "groups"}, mockProvider)
		require.NoError(t, err)
		authRouter.SetGroupsFilter(filter)

		var stored string
		router := gin.New()
		router.Use(sessions.Sessions("session", cookie.NewStore([]byte("test-secret"))))
		authRouter.SetupRoutes(router)
		router.GET("/check-session", func(c *gin.Context) {
			if v, ok := sessions.Default(c).Get(SessionKeyUserInfo).(string); ok {
				stored = v
			}
			c.String(http.StatusOK, "ok")
		})

		server := httptest.NewServer(router)
		defer server.Close()
		client := setupClient()

		resp, err := client.Get(server.URL + "/.auth/test")
		require.NoError(t, err)
		resp.Body.Close()

		callback, err := client.Get(server.URL + "/.auth/test/callback?state=" + state)
		require.NoError(t, err)
		callback.Body.Close()

		resp, err = client.Get(server.URL + "/check-session")
		require.NoError(t, err)
		resp.Body.Close()
		return callback, stored
	}

	t.Run("unfiltered login fails at the callback", func(t *testing.T) {
		resp, stored := run(t, nil)
		require.Equal(t, http.StatusInternalServerError, resp.StatusCode)
		require.Empty(t, stored)
	})

	t.Run("filtered login completes with only the kept groups", func(t *testing.T) {
		f, err := NewGroupsFilter([]string{"team-*", "admins"})
		require.NoError(t, err)
		resp, stored := run(t, f)
		require.Equal(t, http.StatusFound, resp.StatusCode)

		var parsed map[string]any
		require.NoError(t, json.Unmarshal([]byte(stored), &parsed))
		require.Equal(t, "user@example.com", parsed["email"])
		require.Equal(t, []any{"team-a", "team-b", "admins"}, parsed["groups"])
	})
}
