package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/pkg/utils"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type githubProvider struct {
	endpoint     string
	oauth2       oauth2.Config
	allowedUsers []string
	allowedOrgs  []string
}

func NewGithubProvider(clientID, clientSecret, externalURL string, allowedUsers []string, allowedOrgs []string) (Provider, error) {
	r, err := url.JoinPath(externalURL, GitHubCallbackEndpoint)
	if err != nil {
		return nil, err
	}
	scopes := []string{}
	if len(allowedOrgs) > 0 {
		scopes = append(scopes, "read:org")
	}
	return &githubProvider{
		endpoint: "https://api.github.com",
		oauth2: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  r,
			Scopes:       scopes,
			Endpoint:     github.Endpoint,
		},
		allowedUsers: allowedUsers,
		allowedOrgs:  allowedOrgs,
	}, nil
}

func (p *githubProvider) SetApiEndpoint(u string) {
	p.endpoint = u
}

func (p *githubProvider) SetOAuth2Endpoint(cfg oauth2.Endpoint) {
	p.oauth2.Endpoint = cfg
}

func (p *githubProvider) Name() string {
	return "GitHub"
}

func (p *githubProvider) Type() string {
	return "github"
}

func (p *githubProvider) RedirectURL() string {
	return GitHubCallbackEndpoint
}

func (p *githubProvider) AuthURL() string {
	return GitHubAuthEndpoint
}

func (p *githubProvider) AuthCodeURL(state string) (string, error) {
	authURL := p.oauth2.AuthCodeURL(state)
	return authURL, nil
}

func (p *githubProvider) Exchange(c *gin.Context, state string) (*oauth2.Token, error) {
	if c.Query("state") != state {
		return nil, errors.New("invalid OAuth state")
	}
	code := c.Query("code")
	token, err := p.oauth2.Exchange(c, code)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (p *githubProvider) Authorization(ctx context.Context, token *oauth2.Token) (bool, string, error) {
	client := p.oauth2.Client(ctx, token)
	resp, err := client.Get(utils.Must(url.JoinPath(p.endpoint, "/user")))
	if err != nil {
		return false, "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, "", errors.New("failed to get user info from GitHub API: " + resp.Status)
	}
	defer resp.Body.Close()

	var userInfo struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return false, "", err
	}

	if len(p.allowedUsers) == 0 && len(p.allowedOrgs) == 0 {
		return true, userInfo.Login, nil
	}

	if slices.Contains(p.allowedUsers, userInfo.Login) {
		return true, userInfo.Login, nil
	}

	allowedOrgTeams := []string{}
	allowedOrgs := []string{}
	for _, allowedOrg := range p.allowedOrgs {
		if strings.Contains(allowedOrg, ":") {
			allowedOrgTeams = append(allowedOrgTeams, allowedOrg)
		} else {
			allowedOrgs = append(allowedOrgs, allowedOrg)
		}
	}

	if len(allowedOrgs) > 0 {
		resp, err = client.Get(utils.Must(url.JoinPath(p.endpoint, "/user/orgs")))
		if err != nil {
			return false, "", err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return false, "", errors.New("failed to get user info from GitHub API: " + resp.Status)
		}
		defer resp.Body.Close()
		var orgInfo []struct {
			Login string `json:"login"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&orgInfo); err != nil {
			return false, "", err
		}
		for _, o := range orgInfo {
			if slices.Contains(allowedOrgs, o.Login) {
				return true, userInfo.Login, nil
			}
		}
	}
	if len(allowedOrgTeams) > 0 {
		resp, err = client.Get(utils.Must(url.JoinPath(p.endpoint, "/user/teams")))
		if err != nil {
			return false, "", err
		}
		if resp.StatusCode < 200 || resp.StatusCode >= 300 {
			return false, "", errors.New("failed to get user info from GitHub API: " + resp.Status)
		}
		defer resp.Body.Close()
		var teamInfo []struct {
			Organization struct {
				Login string `json:"login"`
			} `json:"organization"`
			Slug string `json:"slug"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&teamInfo); err != nil {
			return false, "", err
		}
		for _, team := range teamInfo {
			if slices.Contains(allowedOrgTeams, team.Organization.Login+":"+team.Slug) {
				return true, userInfo.Login, nil
			}
		}
	}

	return false, userInfo.Login, nil
}
