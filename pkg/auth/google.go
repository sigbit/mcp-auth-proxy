package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/url"
	"slices"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type googleProvider struct {
	userinfoEndpoint  string
	oauth2            oauth2.Config
	allowedUsers      []string
	allowedWorkspaces []string
}

func NewGoogleProvider(externalURL, clientID, clientSecret string, allowedUsers []string, allowedWorkspaces []string) (Provider, error) {
	r, err := url.JoinPath(externalURL, GoogleCallbackEndpoint)
	if err != nil {
		return nil, err
	}
	return &googleProvider{
		userinfoEndpoint: "https://openidconnect.googleapis.com/v1/userinfo",
		oauth2: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  r,
			Scopes:       []string{"openid profile email"},
			Endpoint:     google.Endpoint,
		},
		allowedUsers:      allowedUsers,
		allowedWorkspaces: allowedWorkspaces,
	}, nil
}

func (p *googleProvider) SetUserinfoEndpoint(u string) {
	p.userinfoEndpoint = u
}

func (p *googleProvider) SetOAuth2Endpoint(cfg oauth2.Endpoint) {
	p.oauth2.Endpoint = cfg
}

func (p *googleProvider) Name() string {
	return "Google"
}

func (p *googleProvider) Type() string {
	return "google"
}

func (p *googleProvider) RedirectURL() string {
	return GoogleCallbackEndpoint
}

func (p *googleProvider) AuthCodeURL(state string) (string, error) {
	opts := []oauth2.AuthCodeOption{}
	if len(p.allowedUsers) == 0 && len(p.allowedWorkspaces) == 1 {
		opts = append(opts, oauth2.SetAuthURLParam("hd", p.allowedWorkspaces[0]))
	}
	authURL := p.oauth2.AuthCodeURL(state, opts...)
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

func (p *googleProvider) Authorization(ctx context.Context, token *oauth2.Token) (bool, string, error) {
	client := p.oauth2.Client(ctx, token)
	resp, err := client.Get(p.userinfoEndpoint)
	if err != nil {
		return false, "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return false, "", errors.New("failed to get user info from Google API: " + resp.Status)
	}
	defer resp.Body.Close()

	var userInfo struct {
		Sub   string `json:"sub"`
		Name  string `json:"name"`
		Email string `json:"email"`
		HD    string `json:"hd"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&userInfo); err != nil {
		return false, "", err
	}

	if len(p.allowedUsers) == 0 && len(p.allowedWorkspaces) == 0 {
		return true, userInfo.Email, nil
	}

	if slices.Contains(p.allowedUsers, userInfo.Email) {
		return true, userInfo.Email, nil
	}

	if slices.Contains(p.allowedWorkspaces, userInfo.HD) {
		return true, userInfo.Email, nil
	}

	return false, userInfo.Email, nil
}
