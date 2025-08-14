package main

import (
	"os"

	"github.com/sigbit/mcp-auth-proxy/pkg/proxy"
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
	var globalSecret string

	rootCmd := &cobra.Command{
		Use: "mcp-warp",
		Run: func(cmd *cobra.Command, args []string) {
			if err := proxy.Run(listen, dataPath, externalURL, globalSecret); err != nil {
				panic(err)
			}
		},
	}

	rootCmd.Flags().StringVarP(&listen, "listen", "l", getEnvWithDefault("LISTEN", ":8080"), "Address to listen on")
	rootCmd.Flags().StringVarP(&dataPath, "data", "d", getEnvWithDefault("DATA_PATH", "./data"), "Path to the data directory")
	rootCmd.Flags().StringVarP(&externalURL, "external-url", "e", getEnvWithDefault("EXTERNAL_URL", "http://localhost:8080"), "External URL for the proxy")
	rootCmd.Flags().StringVarP(&globalSecret, "global-secret", "s", getEnvWithDefault("GLOBAL_SECRET", "supersecret"), "Global secret for the proxy")

	if err := rootCmd.Execute(); err != nil {
		panic(err)
	}
}
