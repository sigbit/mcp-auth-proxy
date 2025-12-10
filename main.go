package main

import (
	"os"
	"strings"

	mcpproxy "github.com/sigbit/mcp-auth-proxy/pkg/mcp-proxy"
	"github.com/spf13/cobra"
)

func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvBoolWithDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if strings.ToLower(value) == "true" || value == "1" {
			return true
		}
		return false
	}
	return defaultValue
}

// splitWithEscapes splits a string by delimiter, respecting escape sequences
// e.g., "a,b\,c,d" with delimiter "," returns ["a", "b,c", "d"]
func splitWithEscapes(s, delimiter string) []string {
	if s == "" {
		return []string{}
	}

	var result []string
	var current strings.Builder
	escaped := false

	for i := 0; i < len(s); i++ {
		if escaped {
			current.WriteByte(s[i])
			escaped = false
		} else if s[i] == '\\' && i+1 < len(s) {
			// Check if next character is the delimiter
			if strings.HasPrefix(s[i+1:], delimiter) {
				// Skip the backslash and add the delimiter character
				escaped = true
			} else {
				// Not escaping delimiter, keep the backslash
				current.WriteByte(s[i])
			}
		} else if strings.HasPrefix(s[i:], delimiter) {
			// Found unescaped delimiter
			result = append(result, strings.TrimSpace(current.String()))
			current.Reset()
			i += len(delimiter) - 1 // -1 because loop will increment
		} else {
			current.WriteByte(s[i])
		}
	}

	// Add the last part
	result = append(result, strings.TrimSpace(current.String()))
	return result
}

type proxyRunnerFunc func(
	listen string,
	tlsListen string,
	autoTLS bool,
	tlsHost string,
	tlsDirectoryURL string,
	tlsAcceptTOS bool,
	tlsCertFile string,
	tlsKeyFile string,
	dataPath string,
	repositoryBackend string,
	repositoryDSN string,
	externalURL string,
	googleClientID string,
	googleClientSecret string,
	googleAllowedUsers []string,
	googleAllowedWorkspaces []string,
	githubClientID string,
	githubClientSecret string,
	githubAllowedUsers []string,
	githubAllowedOrgs []string,
	oidcConfigurationURL string,
	oidcClientID string,
	oidcClientSecret string,
	oidcScopes []string,
	oidcUserIDField string,
	oidcProviderName string,
	oidcAllowedUsers []string,
	oidcAllowedUsersGlob []string,
	noProviderAutoSelect bool,
	password string,
	passwordHash string,
	trustedProxy []string,
	proxyHeaders []string,
	proxyBearerToken string,
	proxyTarget []string,
	httpStreamingOnly bool,
) error

func main() {
	if err := newRootCommand(mcpproxy.Run).Execute(); err != nil {
		panic(err)
	}
}

func newRootCommand(run proxyRunnerFunc) *cobra.Command {
	var listen string
	var tlsListen string
	var noAutoTLS bool
	var tlsHost string
	var tlsDirectoryURL string
	var tlsAcceptTOS bool
	var tlsCertFile string
	var tlsKeyFile string
	var dataPath string
	var repositoryBackend string
	var repositoryDSN string
	var externalURL string
	var googleClientID string
	var googleClientSecret string
	var googleAllowedUsers string
	var googleAllowedWorkspaces string
	var githubClientID string
	var githubClientSecret string
	var githubAllowedUsers string
	var githubAllowedOrgs string
	var oidcConfigurationURL string
	var oidcClientID string
	var oidcClientSecret string
	var oidcScopes string
	var oidcUserIDField string
	var oidcProviderName string
	var oidcAllowedUsers string
	var oidcAllowedUsersGlob string
	var noProviderAutoSelect bool
	var password string
	var passwordHash string
	var proxyBearerToken string
	var proxyHeaders string
	var httpStreamingOnly bool
	var trustedProxies string

	rootCmd := &cobra.Command{
		Use: "mcp-warp",
		Run: func(cmd *cobra.Command, args []string) {
			var googleAllowedUsersList []string
			if googleAllowedUsers != "" {
				googleAllowedUsersList = strings.Split(googleAllowedUsers, ",")
				for i := range googleAllowedUsersList {
					googleAllowedUsersList[i] = strings.TrimSpace(googleAllowedUsersList[i])
				}
			}

			var googleAllowedWorkspacesList []string
			if googleAllowedWorkspaces != "" {
				googleAllowedWorkspacesList = strings.Split(googleAllowedWorkspaces, ",")
				for i := range googleAllowedWorkspacesList {
					googleAllowedWorkspacesList[i] = strings.TrimSpace(googleAllowedWorkspacesList[i])
				}
			}

			var githubAllowedUsersList []string
			if githubAllowedUsers != "" {
				githubAllowedUsersList = strings.Split(githubAllowedUsers, ",")
				for i := range githubAllowedUsersList {
					githubAllowedUsersList[i] = strings.TrimSpace(githubAllowedUsersList[i])
				}
			}

			var githubAllowedOrgsList []string
			if githubAllowedOrgs != "" {
				githubAllowedOrgsList = strings.Split(githubAllowedOrgs, ",")
				for i := range githubAllowedOrgsList {
					githubAllowedOrgsList[i] = strings.TrimSpace(githubAllowedOrgsList[i])
				}
			}

			var oidcAllowedUsersList []string
			if oidcAllowedUsers != "" {
				oidcAllowedUsersList = strings.Split(oidcAllowedUsers, ",")
				for i := range oidcAllowedUsersList {
					oidcAllowedUsersList[i] = strings.TrimSpace(oidcAllowedUsersList[i])
				}
			}

			var oidcAllowedUsersGlobList []string
			if oidcAllowedUsersGlob != "" {
				oidcAllowedUsersGlobList = splitWithEscapes(oidcAllowedUsersGlob, ",")
			}

			var oidcScopesList []string
			if oidcScopes != "" {
				oidcScopesList = strings.Split(oidcScopes, ",")
				for i := range oidcScopesList {
					oidcScopesList[i] = strings.TrimSpace(oidcScopesList[i])
				}
			} else {
				oidcScopesList = []string{"openid", "profile", "email"}
			}

			var trustedProxiesList []string
			if trustedProxies != "" {
				trustedProxiesList = strings.Split(trustedProxies, ",")
				for i := range trustedProxiesList {
					trustedProxiesList[i] = strings.TrimSpace(trustedProxiesList[i])
				}
			}

			// Parse proxy headers into slice
			var proxyHeadersList []string
			if proxyHeaders != "" {
				headersList := strings.Split(proxyHeaders, ",")
				for _, header := range headersList {
					proxyHeadersList = append(proxyHeadersList, strings.TrimSpace(header))
				}
			}

			if err := run(
				listen,
				tlsListen,
				(!noAutoTLS) || tlsCertFile != "" || tlsKeyFile != "",
				tlsHost,
				tlsDirectoryURL,
				tlsAcceptTOS,
				tlsCertFile,
				tlsKeyFile,
				dataPath,
				repositoryBackend,
				repositoryDSN,
				externalURL,
				googleClientID,
				googleClientSecret,
				googleAllowedUsersList,
				googleAllowedWorkspacesList,
				githubClientID,
				githubClientSecret,
				githubAllowedUsersList,
				githubAllowedOrgsList,
				oidcConfigurationURL,
				oidcClientID,
				oidcClientSecret,
				oidcScopesList,
				oidcUserIDField,
				oidcProviderName,
				oidcAllowedUsersList,
				oidcAllowedUsersGlobList,
				noProviderAutoSelect,
				password,
				passwordHash,
				trustedProxiesList,
				proxyHeadersList,
				proxyBearerToken,
				args,
				httpStreamingOnly,
			); err != nil {
				panic(err)
			}
		},
	}

	rootCmd.Flags().StringVar(&listen, "listen", getEnvWithDefault("LISTEN", ":80"), "Address to listen on")
	rootCmd.Flags().StringVar(&tlsListen, "tls-listen", getEnvWithDefault("TLS_LISTEN", ":443"), "Address to listen on for TLS")
	rootCmd.Flags().BoolVar(&noAutoTLS, "no-auto-tls", getEnvBoolWithDefault("NO_AUTO_TLS", false), "Disable automatic TLS host detection from externalURL")
	rootCmd.Flags().StringVarP(&tlsHost, "tls-host", "H", getEnvWithDefault("TLS_HOST", ""), "Host name for automatic TLS certificate provisioning")
	rootCmd.Flags().StringVar(&tlsDirectoryURL, "tls-directory-url", getEnvWithDefault("TLS_DIRECTORY_URL", "https://acme-v02.api.letsencrypt.org/directory"), "ACME directory URL for TLS certificates")
	rootCmd.Flags().BoolVar(&tlsAcceptTOS, "tls-accept-tos", getEnvBoolWithDefault("TLS_ACCEPT_TOS", false), "Accept TLS terms of service")
	rootCmd.Flags().StringVar(&tlsCertFile, "tls-cert-file", getEnvWithDefault("TLS_CERT_FILE", ""), "Path to TLS certificate file (PEM). Requires --tls-key-file")
	rootCmd.Flags().StringVar(&tlsKeyFile, "tls-key-file", getEnvWithDefault("TLS_KEY_FILE", ""), "Path to TLS private key file (PEM). Requires --tls-cert-file")
	rootCmd.Flags().StringVarP(&dataPath, "data-path", "d", getEnvWithDefault("DATA_PATH", "./data"), "Path to the data directory")
	rootCmd.Flags().StringVar(&repositoryBackend, "repository-backend", getEnvWithDefault("REPOSITORY_BACKEND", "local"), "Repository backend to use: local, sqlite, postgres, or mysql")
	rootCmd.Flags().StringVar(&repositoryDSN, "repository-dsn", getEnvWithDefault("REPOSITORY_DSN", ""), "DSN passed directly to the SQL driver (required when repository-backend is sqlite/postgres/mysql)")
	rootCmd.Flags().StringVarP(&externalURL, "external-url", "e", getEnvWithDefault("EXTERNAL_URL", "http://localhost"), "External URL for the proxy")

	// Google OAuth configuration
	rootCmd.Flags().StringVar(&googleClientID, "google-client-id", getEnvWithDefault("GOOGLE_CLIENT_ID", ""), "Google OAuth client ID")
	rootCmd.Flags().StringVar(&googleClientSecret, "google-client-secret", getEnvWithDefault("GOOGLE_CLIENT_SECRET", ""), "Google OAuth client secret")
	rootCmd.Flags().StringVar(&googleAllowedUsers, "google-allowed-users", getEnvWithDefault("GOOGLE_ALLOWED_USERS", ""), "Comma-separated list of allowed Google users (emails)")
	rootCmd.Flags().StringVar(&googleAllowedWorkspaces, "google-allowed-workspaces", getEnvWithDefault("GOOGLE_ALLOWED_WORKSPACES", ""), "Comma-separated list of allowed Google workspaces")

	// GitHub OAuth configuration
	rootCmd.Flags().StringVar(&githubClientID, "github-client-id", getEnvWithDefault("GITHUB_CLIENT_ID", ""), "GitHub OAuth client ID")
	rootCmd.Flags().StringVar(&githubClientSecret, "github-client-secret", getEnvWithDefault("GITHUB_CLIENT_SECRET", ""), "GitHub OAuth client secret")
	rootCmd.Flags().StringVar(&githubAllowedUsers, "github-allowed-users", getEnvWithDefault("GITHUB_ALLOWED_USERS", ""), "Comma-separated list of allowed GitHub users (usernames)")
	rootCmd.Flags().StringVar(&githubAllowedOrgs, "github-allowed-orgs", getEnvWithDefault("GITHUB_ALLOWED_ORGS", ""), "Comma-separated list of allowed GitHub organizations. You can also restrict access to specific teams using the format `Org:Team`")

	// OIDC configuration
	rootCmd.Flags().StringVar(&oidcConfigurationURL, "oidc-configuration-url", getEnvWithDefault("OIDC_CONFIGURATION_URL", ""), "OIDC configuration URL")
	rootCmd.Flags().StringVar(&oidcClientID, "oidc-client-id", getEnvWithDefault("OIDC_CLIENT_ID", ""), "OIDC client ID")
	rootCmd.Flags().StringVar(&oidcClientSecret, "oidc-client-secret", getEnvWithDefault("OIDC_CLIENT_SECRET", ""), "OIDC client secret")
	rootCmd.Flags().StringVar(&oidcScopes, "oidc-scopes", getEnvWithDefault("OIDC_SCOPES", "openid,profile,email"), "Comma-separated list of OIDC scopes")
	rootCmd.Flags().StringVar(&oidcUserIDField, "oidc-user-id-field", getEnvWithDefault("OIDC_USER_ID_FIELD", "/email"), "JSON pointer to user ID field in userinfo endpoint response")
	rootCmd.Flags().StringVar(&oidcProviderName, "oidc-provider-name", getEnvWithDefault("OIDC_PROVIDER_NAME", "OIDC"), "Display name for OIDC provider")
	rootCmd.Flags().StringVar(&oidcAllowedUsers, "oidc-allowed-users", getEnvWithDefault("OIDC_ALLOWED_USERS", ""), "Comma-separated list of allowed OIDC users")
	rootCmd.Flags().StringVar(&oidcAllowedUsersGlob, "oidc-allowed-users-glob", getEnvWithDefault("OIDC_ALLOWED_USERS_GLOB", ""), "Comma-separated list of glob patterns for allowed OIDC users")

	// Password authentication
	rootCmd.Flags().BoolVar(&noProviderAutoSelect, "no-provider-auto-select", getEnvBoolWithDefault("NO_PROVIDER_AUTO_SELECT", false), "Disable auto-redirect when only one OAuth/OIDC provider is configured and no password is set")
	rootCmd.Flags().StringVar(&password, "password", getEnvWithDefault("PASSWORD", ""), "Plain text password for authentication (will be hashed with bcrypt)")
	rootCmd.Flags().StringVar(&passwordHash, "password-hash", getEnvWithDefault("PASSWORD_HASH", ""), "Bcrypt hash of password for authentication")

	// Proxy headers configuration
	rootCmd.Flags().StringVar(&proxyBearerToken, "proxy-bearer-token", getEnvWithDefault("PROXY_BEARER_TOKEN", ""), "Bearer token to add to Authorization header when proxying requests")
	rootCmd.Flags().StringVar(&trustedProxies, "trusted-proxies", getEnvWithDefault("TRUSTED_PROXIES", ""), "Comma-separated list of trusted proxies (IP addresses or CIDR ranges)")
	rootCmd.Flags().StringVar(&proxyHeaders, "proxy-headers", getEnvWithDefault("PROXY_HEADERS", ""), "Comma-separated list of headers to add when proxying requests (format: Header1:Value1,Header2:Value2)")
	rootCmd.Flags().BoolVar(&httpStreamingOnly, "http-streaming-only", getEnvBoolWithDefault("HTTP_STREAMING_ONLY", false), "Reject SSE (GET) requests and keep the backend in HTTP streaming-only mode")

	return rootCmd
}
