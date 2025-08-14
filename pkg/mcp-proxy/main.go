package mcpproxy

import (
	"fmt"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/blendle/zapdriver"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/pkg/idp"
	"github.com/sigbit/mcp-auth-proxy/pkg/repository"
	"github.com/sigbit/mcp-auth-proxy/pkg/utils"
	"go.uber.org/zap"
)

func Run(
	listen string,
	dataPath string,
	externalURL string,
	globalSecret string,
) error {
	parsedExternalURL, err := url.Parse(externalURL)
	if err != nil {
		return fmt.Errorf("failed to parse external URL: %w", err)
	}
	if parsedExternalURL.Path != "" {
		return fmt.Errorf("external URL must not have a path, got: %s", parsedExternalURL.Path)
	}

	var config zap.Config
	if os.Getenv("MODE") == "debug" {
		gin.SetMode(gin.DebugMode)
		config = zap.NewDevelopmentConfig()
	} else {
		gin.SetMode(gin.ReleaseMode)
		config = zapdriver.NewProductionConfig()
	}
	logger, err := config.Build()
	if err != nil {
		return fmt.Errorf("failed to build logger: %w", err)
	}
	if err := os.MkdirAll(dataPath, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create database directory: %w", err)
	}

	repo, err := repository.NewKVSRepository(path.Join(dataPath, "db"), "mcp-oauth-proxy")
	if err != nil {
		return fmt.Errorf("failed to create repository: %w", err)
	}

	privKey, err := utils.LoadOrGeneratePrivateKey(path.Join(dataPath, "private_key.pem"))
	if err != nil {
		return fmt.Errorf("failed to load or generate private key: %w", err)
	}
	idpRouter, err := idp.NewIDPRouter(repo, privKey, logger, externalURL, globalSecret)
	if err != nil {
		return fmt.Errorf("failed to create IDP router: %w", err)
	}

	router := gin.New()
	router.Use(ginzap.Ginzap(logger, time.RFC3339, true))
	router.Use(ginzap.RecoveryWithZap(logger, true))
	idpRouter.SetupRoutes(router)

	logger.Info("Starting server", zap.String("listen", listen))
	return router.Run(listen)
}
