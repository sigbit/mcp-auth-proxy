package mcpproxy

import (
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"time"

	"github.com/blendle/zapdriver"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/pkg/idp"
	"github.com/sigbit/mcp-auth-proxy/pkg/proxy"
	"github.com/sigbit/mcp-auth-proxy/pkg/repository"
	"github.com/sigbit/mcp-auth-proxy/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

func Run(
	listen string,
	listenTLS string,
	tlsHost string,
	tlsDirectoryURL string,
	tlsAcceptTOS bool,
	dataPath string,
	externalURL string,
	proxyURL string,
	globalSecret string,
	googleClientID string,
	googleClientSecret string,
	googleAllowedUsers []string,
	githubClientID string,
	githubClientSecret string,
	githubAllowedUsers []string,
	password string,
	passwordHash string,
) error {
	parsedExternalURL, err := url.Parse(externalURL)
	if err != nil {
		return fmt.Errorf("failed to parse external URL: %w", err)
	}
	if parsedExternalURL.Path != "" {
		return fmt.Errorf("external URL must not have a path, got: %s", parsedExternalURL.Path)
	}
	sha256Hash := sha256.Sum256([]byte(globalSecret))
	secret := sha256Hash[:]

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
	var providers []auth.Provider

	// Add Google provider if configured
	if googleClientID != "" && googleClientSecret != "" {
		googleProvider, err := auth.NewGoogleProvider(externalURL, googleClientID, googleClientSecret, googleAllowedUsers)
		if err != nil {
			return fmt.Errorf("failed to create Google provider: %w", err)
		}
		providers = append(providers, googleProvider)
	}

	// Add GitHub provider if configured
	if githubClientID != "" && githubClientSecret != "" {
		githubProvider, err := auth.NewGithubProvider(githubClientID, githubClientSecret, externalURL, githubAllowedUsers)
		if err != nil {
			return fmt.Errorf("failed to create GitHub provider: %w", err)
		}
		providers = append(providers, githubProvider)
	}

	var passwordHashes []string

	// Handle password argument - generate bcrypt hash if provided
	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return fmt.Errorf("failed to generate password hash: %w", err)
		}
		passwordHashes = append(passwordHashes, string(hash))
	}

	// Handle password-hash argument - use directly if provided
	if passwordHash != "" {
		passwordHashes = append(passwordHashes, passwordHash)
	}

	authRouter, err := auth.NewAuthRouter(passwordHashes, providers...)
	if err != nil {
		return fmt.Errorf("failed to create auth router: %w", err)
	}
	idpRouter, err := idp.NewIDPRouter(repo, privKey, logger, externalURL, secret, authRouter)
	if err != nil {
		return fmt.Errorf("failed to create IDP router: %w", err)
	}
	proxyRouter, err := proxy.NewProxyRouter(externalURL, proxyURL, &privKey.PublicKey)
	if err != nil {
		return fmt.Errorf("failed to create proxy router: %w", err)
	}

	router := gin.New()

	router.Use(ginzap.Ginzap(logger, time.RFC3339, true))
	router.Use(ginzap.RecoveryWithZap(logger, true))
	store := cookie.NewStore(secret)
	router.Use(sessions.Sessions("session", store))
	authRouter.SetupRoutes(router)
	idpRouter.SetupRoutes(router)
	proxyRouter.SetupRoutes(router)

	logger.Info("Starting server", zap.String("listen", listen))

	if tlsHost != "" {
		m := autocert.Manager{
			Prompt: func(tosURL string) bool {
				return tlsAcceptTOS
			},
			HostPolicy: autocert.HostWhitelist(tlsHost),
			Cache:      autocert.DirCache(path.Join(dataPath, "certs")),
			Client: &acme.Client{
				DirectoryURL: tlsDirectoryURL,
			},
		}

		errCh := make(chan error)

		go func() {
			s := &http.Server{
				Addr: listen,
				Handler: m.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					host := r.Host
					if host == "" {
						host = r.URL.Host
					}
					target := "https://" + host + r.RequestURI
					http.Redirect(w, r, target, http.StatusMovedPermanently)
				})),
			}
			errCh <- s.ListenAndServe()
		}()

		go func() {
			s := &http.Server{
				Addr:      listenTLS,
				Handler:   router,
				TLSConfig: m.TLSConfig(),
			}
			errCh <- s.ListenAndServeTLS("", "")
		}()

		return <-errCh
	} else {
		return router.Run(listen)
	}
}
