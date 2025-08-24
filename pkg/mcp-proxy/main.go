package mcpproxy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/blendle/zapdriver"
	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	ginzap "github.com/gin-contrib/zap"
	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/pkg/backend"
	"github.com/sigbit/mcp-auth-proxy/pkg/idp"
	"github.com/sigbit/mcp-auth-proxy/pkg/proxy"
	"github.com/sigbit/mcp-auth-proxy/pkg/repository"
	"github.com/sigbit/mcp-auth-proxy/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
)

var ServerShutdownTimeout = 5 * time.Second

func Run(
	listen string,
	tlsListen string,
	autoTLS bool,
	tlsHost string,
	tlsDirectoryURL string,
	tlsAcceptTOS bool,
	dataPath string,
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
	password string,
	passwordHash string,
	trustedProxy []string,
	proxyHeaders []string,
	proxyBearerToken string,
	proxyTarget []string,
) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	parsedExternalURL, err := url.Parse(externalURL)
	if err != nil {
		return fmt.Errorf("failed to parse external URL: %w", err)
	}
	if parsedExternalURL.Path != "" {
		return fmt.Errorf("external URL must not have a path, got: %s", parsedExternalURL.Path)
	}

	secret, err := utils.LoadOrGenerateSecret(path.Join(dataPath, "secret"))
	if err != nil {
		return fmt.Errorf("failed to load or generate secret: %w", err)
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

	if len(proxyTarget) == 0 {
		return fmt.Errorf("proxy target must be specified")
	}
	var be backend.Backend
	var beHandler http.Handler
	if proxyURL, err := url.Parse(proxyTarget[0]); err == nil && (proxyURL.Scheme == "http" || proxyURL.Scheme == "https") {
		var err error
		be, err = backend.NewTransparentBackend(logger, proxyURL, trustedProxy)
		if err != nil {
			return fmt.Errorf("failed to create transparent backend: %w", err)
		}
		beHandler, err = be.Run(ctx)
		if err != nil {
			return fmt.Errorf("failed to create transparent backend: %w", err)
		}
	} else {
		be = backend.NewProxyBackend(logger, proxyTarget)
		beHandler, err = be.Run(ctx)
		if err != nil {
			return fmt.Errorf("failed to create proxy backend: %w", err)
		}
	}

	// Convert headers slice to map and integrate bearer token
	proxyHeadersMap := http.Header{}
	for _, header := range proxyHeaders {
		parts := strings.SplitN(header, ":", 2)
		if len(parts) != 2 || strings.TrimSpace(parts[0]) == "" || strings.TrimSpace(parts[1]) == "" {
			return fmt.Errorf("invalid proxy header format: %s", header)
		}
		proxyHeadersMap.Add(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
	}

	// Add bearer token as Authorization header if provided
	if proxyBearerToken != "" {
		if proxyHeadersMap.Get("Authorization") != "" {
			logger.Warn("Authorization header already set, overwriting with bearer token")
		}
		proxyHeadersMap.Set("Authorization", "Bearer "+proxyBearerToken)
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
		googleProvider, err := auth.NewGoogleProvider(externalURL, googleClientID, googleClientSecret, googleAllowedUsers, googleAllowedWorkspaces)
		if err != nil {
			return fmt.Errorf("failed to create Google provider: %w", err)
		}
		providers = append(providers, googleProvider)
	}

	// Add GitHub provider if configured
	if githubClientID != "" && githubClientSecret != "" {
		githubProvider, err := auth.NewGithubProvider(githubClientID, githubClientSecret, externalURL, githubAllowedUsers, githubAllowedOrgs)
		if err != nil {
			return fmt.Errorf("failed to create GitHub provider: %w", err)
		}
		providers = append(providers, githubProvider)
	}

	// Add OIDC provider if configured
	if oidcConfigurationURL != "" && oidcClientID != "" && oidcClientSecret != "" {
		oidcProvider, err := auth.NewOIDCProvider(
			oidcConfigurationURL,
			oidcScopes,
			oidcUserIDField,
			oidcProviderName,
			externalURL,
			oidcClientID,
			oidcClientSecret,
			oidcAllowedUsers,
		)
		if err != nil {
			return fmt.Errorf("failed to create OIDC provider: %w", err)
		}
		providers = append(providers, oidcProvider)
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
	proxyRouter, err := proxy.NewProxyRouter(externalURL, beHandler, &privKey.PublicKey, proxyHeadersMap)
	if err != nil {
		return fmt.Errorf("failed to create proxy router: %w", err)
	}

	router := gin.New()
	router.SetTrustedProxies(trustedProxy)

	router.Use(ginzap.Ginzap(logger, time.RFC3339, true))
	router.Use(ginzap.RecoveryWithZap(logger, true))
	store := cookie.NewStore(secret)
	store.Options(sessions.Options{
		Path:     "/",
		MaxAge:   600,
		HttpOnly: true,
		Secure:   false,
		SameSite: http.SameSiteLaxMode,
	})
	router.Use(sessions.Sessions("session", store))
	authRouter.SetupRoutes(router)
	idpRouter.SetupRoutes(router)
	proxyRouter.SetupRoutes(router)

	var tlsHostDetected bool
	if autoTLS &&
		tlsHost == "" &&
		parsedExternalURL.Scheme == "https" &&
		parsedExternalURL.Host != "localhost" {
		tlsHost = parsedExternalURL.Host
		tlsHostDetected = true
	}

	exit := make(chan struct{}, 3)
	var wg sync.WaitGroup
	errs := []error{}
	lock := sync.Mutex{}

	if tlsHost != "" {
		if !tlsAcceptTOS {
			if tlsHostDetected {
				return errors.New("TLS host is auto-detected, but tlsAcceptTOS is not set to true. Please agree to the TOS or set noAutoTLS to true")
			} else {
				return errors.New("TLS is enabled, but tlsAcceptTOS is not set to true. Please explicitly agree to the TOS")
			}
		}

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

		httpServer := &http.Server{
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
		httpsServer := &http.Server{
			Addr:      tlsListen,
			Handler:   router,
			TLSConfig: m.TLSConfig(),
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("HTTP server closed")
			exit <- struct{}{}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTP server shutdown error", zap.Error(shutdownErr))
			}
		}()

		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpsServer.ListenAndServeTLS("", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("HTTPS server closed")
			exit <- struct{}{}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpsServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTPS server shutdown error", zap.Error(shutdownErr))
			}
		}()
	} else {
		httpServer := &http.Server{
			Addr:    listen,
			Handler: router,
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := httpServer.ListenAndServe()
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			exit <- struct{}{}
		}()
		go func() {
			<-ctx.Done()
			shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), ServerShutdownTimeout)
			defer shutdownCancel()
			if shutdownErr := httpServer.Shutdown(shutdownCtx); shutdownErr != nil {
				logger.Warn("HTTP server shutdown error", zap.Error(shutdownErr))
			}
		}()
	}

	if be != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := be.Wait(); err != nil && !errors.Is(ctx.Err(), context.Canceled) {
				lock.Lock()
				errs = append(errs, err)
				lock.Unlock()
			}
			logger.Debug("proxy backend closed")
			exit <- struct{}{}
		}()
	}

	if tlsHost != "" {
		logger.Info("Starting server", zap.Strings("listen", []string{listen, tlsListen}))
	} else {
		logger.Info("Starting server", zap.Strings("listen", []string{listen}))
	}
	<-exit
	stop()
	wg.Wait()
	return errors.Join(errs...)
}
