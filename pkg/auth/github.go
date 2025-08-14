package auth

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type githubProvider struct {
	oauth2       oauth2.Config
	allowedUsers []string
}

func NewGithubProvider(clientID, clientSecret, externalURL string, allowedUsers []string) (Provider, error) {
	r, err := url.JoinPath(externalURL, GithubCallbackEndpoint)
	if err != nil {
		return nil, err
	}
	return &githubProvider{
		oauth2: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  r,
			Scopes:       []string{"user:email"},
			Endpoint:     github.Endpoint,
		},
		allowedUsers: allowedUsers,
	}, nil
}

func (p *githubProvider) Name() string {
	return "GitHub"
}

func (p *githubProvider) RedirectURL() string {
	return GithubCallbackEndpoint
}

func (p *githubProvider) AuthCodeURL(c *gin.Context) (string, error) {
	authURL := p.oauth2.AuthCodeURL("state", oauth2.AccessTypeOffline)
	return authURL, nil
}

func (p *githubProvider) Exchange(c *gin.Context) (*oauth2.Token, error) {
	code := c.Query("code")
	token, err := p.oauth2.Exchange(c, code)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (p *githubProvider) GetUserID(ctx context.Context, token *oauth2.Token) (string, error) {
	client := p.oauth2.Client(ctx, token)
	resp, err := client.Get("https://api.github.com/user")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var userInfo struct {
		ID    uint64 `json:"id"`
		Login string `json:"login"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", err
	}

	return userInfo.Login, nil
}

func (p *githubProvider) Authorization(userid string) (bool, error) {
	if len(p.allowedUsers) == 0 {
		return true, nil
	}

	for _, allowedUser := range p.allowedUsers {
		if allowedUser == userid {
			return true, nil
		}
	}

	return false, nil
}
