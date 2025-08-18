package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type googleProvider struct {
	oauth2       oauth2.Config
	allowedUsers []string
}

func NewGoogleProvider(externalURL, clientID, clientSecret string, allowedUsers []string) (Provider, error) {
	r, err := url.JoinPath(externalURL, GoogleCallbackEndpoint)
	if err != nil {
		return nil, err
	}
	return &googleProvider{
		oauth2: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  r,
			Scopes:       []string{"openid profile email"},
			Endpoint:     google.Endpoint,
		},
		allowedUsers: allowedUsers,
	}, nil
}

func (p *googleProvider) Name() string {
	return "Google"
}

func (p *googleProvider) RedirectURL() string {
	return GoogleCallbackEndpoint
}

func (p *googleProvider) AuthCodeURL(c *gin.Context, state string) (string, error) {
	authURL := p.oauth2.AuthCodeURL(state, oauth2.AccessTypeOffline)
	return authURL, nil
}

func (p *googleProvider) AuthURL() string {
	return GoogleAuthEndpoint
}

func (p *googleProvider) Exchange(c *gin.Context, state string) (*oauth2.Token, error) {
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

func (p *googleProvider) GetUserID(ctx context.Context, token *oauth2.Token) (string, error) {
	client := p.oauth2.Client(ctx, token)
	resp, err := client.Get("https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var userInfo struct {
		Sub   string `json:"sub"`
		Name  string `json:"name"`
		Email string `json:"email"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return "", err
	}

	return userInfo.Email, nil
}

func (p *googleProvider) Authorization(userid string) (bool, error) {
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
