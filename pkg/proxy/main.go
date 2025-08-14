package proxy

import (
	"crypto/rsa"
	"fmt"

	"github.com/sigbit/mcp-auth-proxy/pkg/idp"
	"github.com/sigbit/mcp-auth-proxy/pkg/repository"
	"go.uber.org/zap"
)

func run(
	logger *zap.Logger,
	privKey *rsa.PrivateKey,
	dbPath string,
	externalURL string,
	globalSecret string,
) error {
	repo, err := repository.NewKVSRepository(dbPath, "mcp-oauth-proxy")
	if err != nil {
		return fmt.Errorf("failed to create repository: %w", err)
	}

	idpRouter, err := idp.NewIDPRouter(repo, privKey, logger, externalURL, globalSecret)
	if err != nil {
		return fmt.Errorf("failed to create IDP router: %w", err)
	}
	fmt.Println(idpRouter)

	return nil
}
