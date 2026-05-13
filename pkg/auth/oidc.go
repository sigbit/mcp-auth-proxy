package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"

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
}

func NewOIDCProvider(
	configurationURL string, scopes []string, userIDField string,
	providerName, externalURL, clientID, clientSecret string, allowedUsers []string, allowedUsersGlob []string,
	allowedAttributes map[string][]string, allowedAttributesGlob map[string][]string,
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
	authURL := p.oauth2.AuthCodeURL(state)
	return authURL, nil
}

func (p *oidcProvider) Exchange(c *gin.Context, state string) (*oauth2.Token, error) {
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

// Revalidate implements Revalidator by re-querying the OIDC userinfo endpoint
// using the supplied upstream token. If the access token is expired (or near
// expiry per oauth2 internal skew), the underlying TokenSource will transparently
// use the refresh token to obtain a new one. The (potentially refreshed) token
// is returned so the caller can persist it.
//
// Fatal classification mirrors oauth2-proxy semantics:
//   - HTTP 401/403 from userinfo  -> fatal
//   - oauth2 *RetrieveError whose body contains "invalid_grant" or
//     "invalid_client" (RFC 6749 §5.2) -> fatal
//   - Network / 5xx / decode errors -> non-fatal
func (p *oidcProvider) Revalidate(ctx context.Context, token *oauth2.Token) (bool, *oauth2.Token, error) {
	if token == nil {
		return false, nil, &FatalRevalidationError{Reason: "missing upstream token"}
	}

	ts := p.oauth2.TokenSource(ctx, token)
	refreshed, err := ts.Token()
	if err != nil {
		if isFatalOAuth2Error(err) {
			return false, nil, &FatalRevalidationError{Reason: "token refresh rejected", Err: err}
		}
		return false, nil, fmt.Errorf("token refresh failed: %w", err)
	}

	client := oauth2.NewClient(ctx, oauth2.StaticTokenSource(refreshed))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.userInfoURL, nil)
	if err != nil {
		return false, nil, fmt.Errorf("build userinfo request: %w", err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return false, nil, fmt.Errorf("userinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return false, nil, &FatalRevalidationError{Reason: fmt.Sprintf("userinfo returned %s", resp.Status)}
	case resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices:
		return false, nil, fmt.Errorf("userinfo request failed: %s", resp.Status)
	}

	var obj any
	if err := json.NewDecoder(resp.Body).Decode(&obj); err != nil {
		return false, nil, fmt.Errorf("decode userinfo response: %w", err)
	}
	userInfoMap, ok := obj.(map[string]any)
	if !ok {
		return false, nil, errors.New("userinfo response is not a JSON object")
	}
	v, err := jsonpointer.Get(obj, p.userIDField)
	if err != nil {
		return false, nil, err
	}
	userID, ok := v.(string)
	if !ok {
		return false, nil, errors.New("user ID field is not a string")
	}

	allowed := p.matchAuthorization(userID, userInfoMap)
	return allowed, refreshed, nil
}

// matchAuthorization mirrors the allow-list logic in Authorization, factored
// out so Revalidate can reuse it without re-issuing a userinfo request.
func (p *oidcProvider) matchAuthorization(userID string, userInfo map[string]any) bool {
	if len(p.allowedUsers) == 0 && len(p.allowedUsersGlob) == 0 && len(p.allowedAttributes) == 0 && len(p.allowedAttributesGlob) == 0 {
		return true
	}
	if slices.Contains(p.allowedUsers, userID) {
		return true
	}
	for _, g := range p.allowedUsersGlob {
		if g.Match(userID) {
			return true
		}
	}
	for key, allowedValues := range p.allowedAttributes {
		attrValue, err := jsonpointer.Get(userInfo, key)
		if err != nil {
			continue
		}
		if matchAttributeValue(attrValue, allowedValues) {
			return true
		}
	}
	for key, globs := range p.allowedAttributesGlob {
		attrValue, err := jsonpointer.Get(userInfo, key)
		if err != nil {
			continue
		}
		if matchAttributeGlob(attrValue, globs) {
			return true
		}
	}
	return false
}

// isFatalOAuth2Error returns true for errors that the IdP considers terminal
// per RFC 6749 §5.2 (invalid_grant, invalid_client). Detection mirrors
// oauth2-proxy: substring match on the error body since the upstream
// golang.org/x/oauth2 *RetrieveError stringification varies by version.
func isFatalOAuth2Error(err error) bool {
	if err == nil {
		return false
	}
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		if re.Response != nil && (re.Response.StatusCode == http.StatusUnauthorized || re.Response.StatusCode == http.StatusForbidden) {
			return true
		}
		if re.ErrorCode == "invalid_grant" || re.ErrorCode == "invalid_client" {
			return true
		}
		body := strings.ToLower(string(re.Body))
		if strings.Contains(body, "invalid_grant") || strings.Contains(body, "invalid_client") {
			return true
		}
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "invalid_grant") || strings.Contains(msg, "invalid_client")
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
