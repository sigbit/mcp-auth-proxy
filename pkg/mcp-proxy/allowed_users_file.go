package mcpproxy

import (
	"fmt"

	"github.com/golang-jwt/jwt/v5"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/idp"
)

// allowedUsersFileOption describes the --<provider>-allowed-users-file option
// of one auth provider.
type allowedUsersFileOption struct {
	provider   string // auth.Provider.Type()
	flag       string
	path       string
	configured bool // the provider itself is configured
	otherRules bool // another allow-list option of the provider is set
}

// loadAllowedUsersFiles validates the allowed users file options and opens the
// files, keyed by provider type.
//
// A file is the single source of truth for its provider: the other allow-list
// options of that provider (workspaces, organizations, attributes, ...) cannot
// be re-checked from an issued token, so combining them is rejected instead of
// silently refusing those users on their next request.
func loadAllowedUsersFiles(options []allowedUsersFileOption) (auth.AllowedUsersFiles, error) {
	files := auth.AllowedUsersFiles{}
	for _, option := range options {
		if option.path == "" {
			continue
		}
		if !option.configured {
			return nil, fmt.Errorf("%s is set but the %s provider is not configured", option.flag, option.provider)
		}
		if option.otherRules {
			return nil, fmt.Errorf("%s cannot be combined with the other allow-list options of the %s provider", option.flag, option.provider)
		}
		file, err := auth.NewAllowedUsersFile(option.path)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", option.flag, err)
		}
		files[option.provider] = file
	}
	return files, nil
}

// allowedUsersClaimsAuthorizer re-checks the subject of an access token
// against the allowed users file of the provider that issued it.
func allowedUsersClaimsAuthorizer(files auth.AllowedUsersFiles) func(jwt.MapClaims) bool {
	return func(claims jwt.MapClaims) bool {
		subject, _ := claims["sub"].(string)
		provider, _ := claims[idp.ProviderClaim].(string)
		return files.Allows(provider, subject)
	}
}
