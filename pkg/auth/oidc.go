package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/gobwas/glob"
	"github.com/mattn/go-jsonpointer"
	"golang.org/x/oauth2"
)

type oidcProvider struct {
	oauth2                oauth2.Config
	providerName          string
	userInfoURL           string
	userIDField           string
	allowedUsers          []string
	allowedUsersGlob      []glob.Glob
	allowedAttributes     map[string][]string
	allowedAttributesGlob map[string][]glob.Glob
	// promptValue, if non-empty, is sent as the OIDC `prompt` query parameter
	// on the authorization request. Common values: "login" (force the IdP to
	// show a login screen even when a valid SSO session exists), "consent",
	// "select_account", "none". Useful for IdPs (e.g. Entra ID) where silent
	// SSO would otherwise hide whether MFA was challenged.
	promptValue string
	// pkceVerifiers maps the OAuth `state` to its PKCE code_verifier. The
	// verifier is generated in AuthCodeURL, sent as a code_challenge to the
	// upstream IdP, and consumed in Exchange to fulfill the PKCE flow.
	// Required for OAuth 2.1-compliant IdPs (e.g. Duo SSO) that reject
	// authorization requests without code_challenge.
	pkceVerifiers sync.Map
}

func NewOIDCProvider(
	configurationURL string, scopes []string, userIDField string,
	providerName, externalURL, clientID, clientSecret string, allowedUsers []string, allowedUsersGlob []string,
	allowedAttributes map[string][]string, allowedAttributesGlob map[string][]string,
	promptValue string,
) (Provider, error) {
	resp, err := http.Get(configurationURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("OIDC configuration request failed: %s", resp.Status)
	}
	var cfg struct {
		AuthEndpoint  string `json:"authorization_endpoint"`
		TokenEndpoint string `json:"token_endpoint"`
		UserInfo      string `json:"userinfo_endpoint"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&cfg); err != nil {
		return nil, err
	}
	r, err := url.JoinPath(externalURL, OIDCCallbackEndpoint)
	if err != nil {
		return nil, err
	}

	// Compile glob patterns
	var compiledGlobs []glob.Glob
	for _, pattern := range allowedUsersGlob {
		if pattern != "" {
			g, err := glob.Compile(pattern)
			if err != nil {
				return nil, err
			}
			compiledGlobs = append(compiledGlobs, g)
		}
	}

	// Compile attribute glob patterns
	compiledAttributeGlobs := make(map[string][]glob.Glob)
	for key, patterns := range allowedAttributesGlob {
		for _, pattern := range patterns {
			if pattern != "" {
				g, err := glob.Compile(pattern)
				if err != nil {
					return nil, err
				}
				compiledAttributeGlobs[key] = append(compiledAttributeGlobs[key], g)
			}
		}
	}

	return &oidcProvider{
		oauth2: oauth2.Config{
			ClientID:     clientID,
			ClientSecret: clientSecret,
			RedirectURL:  r,
			Scopes:       scopes,
			Endpoint: oauth2.Endpoint{
				AuthURL:  cfg.AuthEndpoint,
				TokenURL: cfg.TokenEndpoint,
			},
		},
		providerName:          providerName,
		userInfoURL:           cfg.UserInfo,
		userIDField:           userIDField,
		allowedUsers:          allowedUsers,
		allowedUsersGlob:      compiledGlobs,
		allowedAttributes:     allowedAttributes,
		allowedAttributesGlob: compiledAttributeGlobs,
		promptValue:           promptValue,
	}, nil
}

func (p *oidcProvider) Name() string {
	return p.providerName
}

func (p *oidcProvider) Type() string {
	return "oidc"
}

func (p *oidcProvider) RedirectURL() string {
	return OIDCCallbackEndpoint
}

func (p *oidcProvider) AuthURL() string {
	return OIDCAuthEndpoint
}

func (p *oidcProvider) AuthCodeURL(state string) (string, error) {
	verifier := oauth2.GenerateVerifier()
	p.pkceVerifiers.Store(state, verifier)
	opts := []oauth2.AuthCodeOption{oauth2.S256ChallengeOption(verifier)}
	if p.promptValue != "" {
		opts = append(opts, oauth2.SetAuthURLParam("prompt", p.promptValue))
	}
	authURL := p.oauth2.AuthCodeURL(state, opts...)
	return authURL, nil
}

func (p *oidcProvider) Exchange(c *gin.Context, state string) (*oauth2.Token, error) {
	if c.Query("state") != state {
		return nil, errors.New("invalid OAuth state")
	}
	code := c.Query("code")
	var opts []oauth2.AuthCodeOption
	if v, ok := p.pkceVerifiers.LoadAndDelete(state); ok {
		opts = append(opts, oauth2.VerifierOption(v.(string)))
	}
	token, err := p.oauth2.Exchange(c, code, opts...)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (p *oidcProvider) Authorization(ctx context.Context, token *oauth2.Token) (bool, string, map[string]any, error) {
	client := p.oauth2.Client(ctx, token)
	resp, err := client.Get(p.userInfoURL)
	if err != nil {
		return false, "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return false, "", nil, fmt.Errorf("userinfo request failed: %s", resp.Status)
	}
	var obj any
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return false, "", nil, err
	}
	userInfoMap, ok := obj.(map[string]any)
	if !ok {
		return false, "", nil, errors.New("userinfo response is not a JSON object")
	}
	v, err := jsonpointer.Get(obj, p.userIDField)
	if err != nil {
		return false, "", nil, err
	}
	userID, ok := v.(string)
	if !ok {
		return false, "", nil, errors.New("user ID field is not a string")
	}

	// If no restrictions are set, allow all users
	if len(p.allowedUsers) == 0 && len(p.allowedUsersGlob) == 0 && len(p.allowedAttributes) == 0 && len(p.allowedAttributesGlob) == 0 {
		return true, userID, userInfoMap, nil
	}

	// Check exact user matches first
	if slices.Contains(p.allowedUsers, userID) {
		return true, userID, userInfoMap, nil
	}

	// Check user glob patterns
	for _, g := range p.allowedUsersGlob {
		if g.Match(userID) {
			return true, userID, userInfoMap, nil
		}
	}

	// Check exact attribute matches
	for key, allowedValues := range p.allowedAttributes {
		attrValue, err := jsonpointer.Get(obj, key)
		if err != nil {
			continue // Attribute not found, skip
		}
		if matchAttributeValue(attrValue, allowedValues) {
			return true, userID, userInfoMap, nil
		}
	}

	// Check attribute glob patterns
	for key, globs := range p.allowedAttributesGlob {
		attrValue, err := jsonpointer.Get(obj, key)
		if err != nil {
			continue // Attribute not found, skip
		}
		if matchAttributeGlob(attrValue, globs) {
			return true, userID, userInfoMap, nil
		}
	}

	return false, userID, userInfoMap, nil
}

// matchAttributeValue checks if an attribute value matches any of the allowed values.
// Supports string values and arrays of strings.
func matchAttributeValue(attrValue any, allowedValues []string) bool {
	switch v := attrValue.(type) {
	case string:
		return slices.Contains(allowedValues, v)
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				if slices.Contains(allowedValues, s) {
					return true
				}
			}
		}
	}
	return false
}

// matchAttributeGlob checks if an attribute value matches any of the glob patterns.
// Supports string values and arrays of strings.
func matchAttributeGlob(attrValue any, globs []glob.Glob) bool {
	switch v := attrValue.(type) {
	case string:
		for _, g := range globs {
			if g.Match(v) {
				return true
			}
		}
	case []any:
		for _, item := range v {
			if s, ok := item.(string); ok {
				for _, g := range globs {
					if g.Match(s) {
						return true
					}
				}
			}
		}
	}
	return false
}
