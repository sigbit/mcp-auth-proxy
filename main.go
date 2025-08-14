package main

import (
	"os"

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

	rootCmd := &cobra.Command{
		Use: "mcp-warp",
		Run: func(cmd *cobra.Command, args []string) {
			if err := mcpproxy.Run(listen, dataPath, externalURL, proxyURL, globalSecret); err != nil {
				panic(err)
			}
		},
	}

	rootCmd.Flags().StringVarP(&listen, "listen", "l", getEnvWithDefault("LISTEN", ":8081"), "Address to listen on")
	rootCmd.Flags().StringVarP(&dataPath, "data", "d", getEnvWithDefault("DATA_PATH", "./data"), "Path to the data directory")
	rootCmd.Flags().StringVarP(&externalURL, "external-url", "e", getEnvWithDefault("EXTERNAL_URL", "http://localhost:8081"), "External URL for the proxy")
	rootCmd.Flags().StringVarP(&proxyURL, "proxy-url", "p", getEnvWithDefault("PROXY_URL", "http://localhost:8080"), "Proxy URL for the proxy")
	rootCmd.Flags().StringVarP(&globalSecret, "global-secret", "s", getEnvWithDefault("GLOBAL_SECRET", "supersecret"), "Global secret for the proxy")

	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
