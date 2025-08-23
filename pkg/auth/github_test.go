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
	TestGitHubClientID     = "test-client-id"
	TestGitHubClientSecret = "test-client-secret"
	TestGitHubExternalURL  = "http://localhost:8080"
)

func setupGitHubTest(allowedUsers, allowedOrgs []string) (Provider, gin.IRoutes) {
	p, _ := NewGithubProvider(TestGitHubClientID, TestGitHubClientSecret, TestGitHubExternalURL, allowedUsers, allowedOrgs)

	gh := gin.New()
	gh.POST("/login/oauth/access_token", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{
			"access_token": "test-access-token",
		})
	})
	tsgh := httptest.NewServer(gh)
	gp := p.(*githubProvider)
	gp.SetOAuth2Endpoint(oauth2.Endpoint{
		AuthURL:       tsgh.URL + "/login/oauth/authorize",
		TokenURL:      tsgh.URL + "/login/oauth/access_token",
		DeviceAuthURL: tsgh.URL + "/login/device/code",
	})

	ghapi := gin.New()
	tsghapi := httptest.NewServer(ghapi)
	gp.SetApiEndpoint(tsghapi.URL)

	return p, ghapi
}

func TestGitHubProvider(t *testing.T) {
	p, _ := setupGitHubTest([]string{}, []string{})
	require.Equal(t, p.Name(), "GitHub")
	require.Equal(t, p.Type(), "github")
	require.Equal(t, p.RedirectURL(), GitHubCallbackEndpoint)
	require.Equal(t, p.AuthURL(), GitHubAuthEndpoint)

	// check AuthCodeURL
	authCodeURL, err := p.AuthCodeURL("test-state")
	require.NoError(t, err)
	require.NotEmpty(t, authCodeURL)
	authCodeURLObj, err := url.Parse(authCodeURL)
	require.NoError(t, err)
	require.Equal(t, authCodeURLObj.Path, "/login/oauth/authorize")
	require.Equal(t, authCodeURLObj.Query().Get("client_id"), TestGitHubClientID)
	require.Equal(t, authCodeURLObj.Query().Get("redirect_uri"), TestGitHubExternalURL+"/.auth/github/callback")
	require.Equal(t, authCodeURLObj.Query().Get("response_type"), "code")
	require.Equal(t, authCodeURLObj.Query().Get("state"), "test-state")

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

func TestGitHubProviderAuthorization(t *testing.T) {
	tc := []struct {
		name         string
		allowedUsers []string
		allowedOrgs  []string
		userResp     string
		teamsResp    string
		orgsResp     string
		expect       bool
	}{
		{
			name:         "allow all users",
			allowedUsers: []string{},
			allowedOrgs:  []string{},
			userResp:     `{"login": "user1"}`,
			orgsResp:     `[]`,
			teamsResp:    `[]`,
			expect:       true,
		},
		{
			name:         "allow single user",
			allowedUsers: []string{"user1", "user2"},
			allowedOrgs:  []string{},
			userResp:     `{"login": "user1"}`,
			orgsResp:     `[]`,
			teamsResp:    `[]`,
			expect:       true,
		},
		{
			name:         "deny single user",
			allowedUsers: []string{"user1"},
			allowedOrgs:  []string{},
			userResp:     `{"login": "user2"}`,
			orgsResp:     `[]`,
			teamsResp:    `[]`,
			expect:       false,
		},
		{
			name:         "allow by org",
			allowedUsers: []string{},
			allowedOrgs:  []string{"org1"},
			userResp:     `{"login": "user1"}`,
			orgsResp:     `[{"login": "org1"}]`,
			teamsResp:    `[]`,
			expect:       true,
		},
		{
			name:         "deny by org",
			allowedUsers: []string{},
			allowedOrgs:  []string{"org1"},
			userResp:     `{"login": "user1"}`,
			orgsResp:     `[{"login": "org2"}]`,
			teamsResp:    `[]`,
			expect:       false,
		},
		{
			name:         "allow by team",
			allowedUsers: []string{},
			allowedOrgs:  []string{"org1:team1"},
			userResp:     `{"login": "user1"}`,
			orgsResp:     `[]`,
			teamsResp:    `[{"organization": {"login": "org1"}, "slug": "team1"}]`,
			expect:       true,
		},
		{
			name:         "deny by team",
			allowedUsers: []string{},
			allowedOrgs:  []string{"org1:team1"},
			userResp:     `{"login": "user1"}`,
			orgsResp:     `[]`,
			teamsResp:    `[{"organization": {"login": "org1"}, "slug": "team2"}]`,
			expect:       false,
		},
	}

	for _, tt := range tc {
		t.Run(tt.name, func(t *testing.T) {
			p, ghapi := setupGitHubTest(tt.allowedUsers, tt.allowedOrgs)
			userResp := tt.userResp
			orgsResp := tt.orgsResp
			teamsResp := tt.teamsResp
			expect := tt.expect

			ghapi.GET("/user", func(c *gin.Context) {
				c.Data(http.StatusOK, "application/json", []byte(userResp))
			})
			ghapi.GET("/user/orgs", func(c *gin.Context) {
				c.Data(http.StatusOK, "application/json", []byte(orgsResp))
			})
			ghapi.GET("/user/teams", func(c *gin.Context) {
				c.Data(http.StatusOK, "application/json", []byte(teamsResp))
			})

			// Call the Authorization method
			ok, _, err := p.Authorization(context.Background(), &oauth2.Token{AccessToken: "test-access-token"})
			require.NoError(t, err)
			require.Equal(t, expect, ok)
		})
	}
}
