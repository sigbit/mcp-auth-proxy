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

func main() {
	var listen string
	var dataPath string
	var externalURL string
	var proxyURL string
	var globalSecret string
	var googleClientID string
	var googleClientSecret string
	var googleAllowedUsers string
	var githubClientID string
	var githubClientSecret string
	var githubAllowedUsers string

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

			var githubAllowedUsersList []string
			if githubAllowedUsers != "" {
				githubAllowedUsersList = strings.Split(githubAllowedUsers, ",")
				for i := range githubAllowedUsersList {
					githubAllowedUsersList[i] = strings.TrimSpace(githubAllowedUsersList[i])
				}
			}

			if err := mcpproxy.Run(
				listen,
				dataPath,
				externalURL,
				proxyURL,
				globalSecret,
				googleClientID,
				googleClientSecret,
				googleAllowedUsersList,
				githubClientID,
				githubClientSecret,
				githubAllowedUsersList,
			); err != nil {
				panic(err)
			}
		},
	}

	rootCmd.Flags().StringVarP(&listen, "listen", "l", getEnvWithDefault("LISTEN", ":8081"), "Address to listen on")
	rootCmd.Flags().StringVarP(&dataPath, "data", "d", getEnvWithDefault("DATA_PATH", "./data"), "Path to the data directory")
	rootCmd.Flags().StringVarP(&externalURL, "external-url", "e", getEnvWithDefault("EXTERNAL_URL", "http://localhost:8081"), "External URL for the proxy")
	rootCmd.Flags().StringVarP(&proxyURL, "proxy-url", "p", getEnvWithDefault("PROXY_URL", "http://localhost:8080"), "Proxy URL for the proxy")
	rootCmd.Flags().StringVarP(&globalSecret, "global-secret", "s", getEnvWithDefault("GLOBAL_SECRET", "supersecret"), "Global secret for the proxy")
	
	// Google OAuth configuration
	rootCmd.Flags().StringVar(&googleClientID, "google-client-id", getEnvWithDefault("GOOGLE_CLIENT_ID", ""), "Google OAuth client ID")
	rootCmd.Flags().StringVar(&googleClientSecret, "google-client-secret", getEnvWithDefault("GOOGLE_CLIENT_SECRET", ""), "Google OAuth client secret")
	rootCmd.Flags().StringVar(&googleAllowedUsers, "google-allowed-users", getEnvWithDefault("GOOGLE_ALLOWED_USERS", ""), "Comma-separated list of allowed Google users (emails)")
	
	// GitHub OAuth configuration
	rootCmd.Flags().StringVar(&githubClientID, "github-client-id", getEnvWithDefault("GITHUB_CLIENT_ID", ""), "GitHub OAuth client ID")
	rootCmd.Flags().StringVar(&githubClientSecret, "github-client-secret", getEnvWithDefault("GITHUB_CLIENT_SECRET", ""), "GitHub OAuth client secret")
	rootCmd.Flags().StringVar(&githubAllowedUsers, "github-allowed-users", getEnvWithDefault("GITHUB_ALLOWED_USERS", ""), "Comma-separated list of allowed GitHub users (usernames)")

	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
