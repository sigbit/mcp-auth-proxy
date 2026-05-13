package proxy

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mattn/go-jsonpointer"
	"github.com/ory/fosite"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/auth"
	"github.com/sigbit/mcp-auth-proxy/v2/pkg/repository"
	"go.uber.org/zap"
	"golang.org/x/oauth2"
	"golang.org/x/sync/singleflight"
)

type ProxyRouter struct {
	externalURL                string
	proxy                      http.Handler
	publicKey                  *rsa.PublicKey
	proxyHeaders               http.Header
	httpStreamingOnly          bool
	forwardAuthorizationHeader bool
	headerMapping              map[string]string
	headerMappingBase          string

	// Revalidation
	repo                repository.Repository
	providers           map[string]auth.Provider
	revalidateInterval  time.Duration
	revalidateGroup     singleflight.Group
	logger              *zap.Logger
	disableRevalidation bool
}

// Options holds optional dependencies for ProxyRouter, primarily related to
// upstream re-validation (PP023). Zero values disable revalidation entirely.
type Options struct {
	Repo               repository.Repository
	Providers          []auth.Provider
	RevalidateInterval time.Duration
	Logger             *zap.Logger
}

func NewProxyRouter(
	externalURL string,
	proxy http.Handler,
	publicKey *rsa.PublicKey,
	proxyHeaders http.Header,
	httpStreamingOnly bool,
	forwardAuthorizationHeader bool,
	headerMapping map[string]string,
	headerMappingBase string,
	opts *Options,
) (*ProxyRouter, error) {
	r := &ProxyRouter{
		externalURL:                externalURL,
		proxy:                      proxy,
		publicKey:                  publicKey,
		proxyHeaders:               proxyHeaders,
		httpStreamingOnly:          httpStreamingOnly,
		forwardAuthorizationHeader: forwardAuthorizationHeader,
		headerMapping:              headerMapping,
		headerMappingBase:          headerMappingBase,
	}
	if opts != nil {
		r.repo = opts.Repo
		r.revalidateInterval = opts.RevalidateInterval
		r.logger = opts.Logger
		if len(opts.Providers) > 0 {
			r.providers = make(map[string]auth.Provider, len(opts.Providers))
			for _, p := range opts.Providers {
				r.providers[p.Name()] = p
			}
		}
	}
	if r.logger == nil {
		r.logger = zap.NewNop()
	}
	if r.repo == nil || r.revalidateInterval <= 0 || len(r.providers) == 0 {
		r.disableRevalidation = true
	}
	return r, nil
}

const (
	OauthProtectedResourceEndpoint = "/.well-known/oauth-protected-resource"
)

func (p *ProxyRouter) SetupRoutes(router gin.IRouter) {
	router.GET(OauthProtectedResourceEndpoint, p.handleProtectedResource)
	router.Use(p.handleProxy)
}

type protectedResourceResponse struct {
	Resource             string   `json:"resource"`
	AuthorizationServers []string `json:"authorization_servers"`
}

func (p *ProxyRouter) handleProtectedResource(c *gin.Context) {
	c.JSON(http.StatusOK, protectedResourceResponse{
		Resource:             p.externalURL,
		AuthorizationServers: []string{p.externalURL},
	})
}

func (p *ProxyRouter) handleProxy(c *gin.Context) {
	authHeader := c.Request.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	bearerToken := strings.TrimPrefix(authHeader, "Bearer ")

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.publicKey, nil
	}, jwt.WithIssuer(p.externalURL), jwt.WithAudience(p.externalURL))

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	if !p.disableRevalidation {
		if !p.revalidate(c.Request.Context(), claims) {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Session revalidation failed"})
			return
		}
	}

	if p.httpStreamingOnly && isSSEGetRequest(c.Request) {
		c.AbortWithStatusJSON(http.StatusMethodNotAllowed, gin.H{"error": "SSE (GET) streaming is not supported by this backend; use POST-based HTTP streaming instead"})
		return
	}

	if !p.forwardAuthorizationHeader {
		c.Request.Header.Del("Authorization")
	}
	for _, headerName := range p.headerMapping {
		c.Request.Header.Del(headerName)
	}
	for key, values := range p.proxyHeaders {
		if strings.EqualFold(key, "Authorization") {
			c.Request.Header.Del("Authorization")
		}
		for _, value := range values {
			c.Request.Header.Add(key, value)
		}
	}

	if len(p.headerMapping) > 0 {
		var source any = map[string]any(claims)
		if p.headerMappingBase != "/" {
			val, err := jsonpointer.Get(source, p.headerMappingBase)
			if err != nil {
				source = nil
			} else {
				source = val
			}
		}
		if source != nil {
			for pointer, headerName := range p.headerMapping {
				val, err := jsonpointer.Get(source, pointer)
				if err != nil {
					continue
				}
				switch v := val.(type) {
				case string:
					c.Request.Header.Set(headerName, v)
				case []any:
					var parts []string
					for _, item := range v {
						if s, ok := item.(string); ok {
							parts = append(parts, s)
						}
					}
					c.Request.Header.Set(headerName, strings.Join(parts, ","))
				default:
					c.Request.Header.Set(headerName, fmt.Sprintf("%v", v))
				}
			}
		}
	}

	p.proxy.ServeHTTP(c.Writer, c.Request)
}

// revalidate ensures the upstream IdP still considers the user authorized.
// Returns true if the request may proceed.
//
// Behavior:
//   - If the cached upstream session is missing -> reject (force re-login).
//     This protects against tokens issued before this feature shipped.
//   - If LastChecked is within the configured interval -> allow (cache hit).
//   - Otherwise call Provider.Revalidate. On FatalRevalidationError, revoke all
//     downstream tokens for the subject and reject. On any other error, log a
//     warning and allow the request to proceed (oauth2-proxy parity).
func (p *ProxyRouter) revalidate(ctx context.Context, claims jwt.MapClaims) bool {
	subject, _ := claims["sub"].(string)
	if subject == "" {
		// No subject => can't revalidate; conservative behavior is to reject.
		p.logger.Warn("JWT missing sub claim; rejecting")
		return false
	}

	upSess, err := p.repo.GetUpstreamSession(ctx, subject)
	if err != nil {
		if errors.Is(err, fosite.ErrNotFound) {
			p.logger.Info("No upstream session for subject; forcing re-login",
				zap.String("subject", subject))
			return false
		}
		p.logger.Warn("Failed to load upstream session; allowing request",
			zap.String("subject", subject), zap.Error(err))
		return true
	}

	if !upSess.LastChecked.IsZero() && time.Since(upSess.LastChecked) < p.revalidateInterval {
		return true
	}

	provider, ok := p.providers[upSess.Provider]
	if !ok {
		p.logger.Warn("Unknown provider in upstream session; allowing request",
			zap.String("subject", subject), zap.String("provider", upSess.Provider))
		return true
	}
	revalidator, ok := provider.(auth.Revalidator)
	if !ok {
		// Provider does not support revalidation; nothing to do. Bump
		// LastChecked so we don't keep retrying on every request.
		upSess.LastChecked = time.Now().UTC()
		_ = p.repo.PutUpstreamSession(ctx, upSess)
		return true
	}

	type result struct {
		allowed bool
		token   *oauth2.Token
		err     error
	}

	v, _, _ := p.revalidateGroup.Do(subject, func() (any, error) {
		tok := &oauth2.Token{
			AccessToken:  upSess.AccessToken,
			TokenType:    upSess.TokenType,
			RefreshToken: upSess.RefreshToken,
			Expiry:       upSess.Expiry,
		}
		allowed, newTok, err := revalidator.Revalidate(ctx, tok)
		return result{allowed: allowed, token: newTok, err: err}, nil
	})
	res := v.(result)

	var fatal *auth.FatalRevalidationError
	switch {
	case errors.As(res.err, &fatal):
		p.logger.Info("Upstream revalidation rejected; revoking subject's tokens",
			zap.String("subject", subject), zap.String("reason", fatal.Reason))
		p.revokeAllForSubject(ctx, subject)
		return false
	case res.err != nil:
		p.logger.Warn("Upstream revalidation transient failure; allowing",
			zap.String("subject", subject), zap.Error(res.err))
		return true
	case !res.allowed:
		p.logger.Info("User no longer authorized by upstream; revoking",
			zap.String("subject", subject))
		p.revokeAllForSubject(ctx, subject)
		return false
	}

	// Persist refreshed token + bump LastChecked.
	if res.token != nil {
		upSess.AccessToken = res.token.AccessToken
		upSess.TokenType = res.token.TokenType
		if res.token.RefreshToken != "" {
			upSess.RefreshToken = res.token.RefreshToken
		}
		upSess.Expiry = res.token.Expiry
	}
	upSess.LastChecked = time.Now().UTC()
	if err := p.repo.PutUpstreamSession(ctx, upSess); err != nil {
		p.logger.Warn("Failed to persist refreshed upstream session",
			zap.String("subject", subject), zap.Error(err))
	}
	return true
}

// revokeAllForSubject deletes every downstream access-token session known for
// the given subject and removes the upstream-session cache entry. Best-effort:
// individual failures are logged but do not stop the loop.
func (p *ProxyRouter) revokeAllForSubject(ctx context.Context, subject string) {
	sigs, err := p.repo.ListAccessTokensForSubject(ctx, subject)
	if err != nil {
		p.logger.Warn("Failed to enumerate access tokens for subject",
			zap.String("subject", subject), zap.Error(err))
	}
	for _, sig := range sigs {
		if err := p.repo.RevokeAccessToken(ctx, sig); err != nil {
			p.logger.Warn("Failed to revoke access token",
				zap.String("subject", subject), zap.String("signature", sig), zap.Error(err))
		}
	}
	if err := p.repo.DeleteUpstreamSession(ctx, subject); err != nil {
		p.logger.Warn("Failed to delete upstream session",
			zap.String("subject", subject), zap.Error(err))
	}
}

func isSSEGetRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	for value := range strings.SplitSeq(accept, ",") {
		mediaType := strings.TrimSpace(strings.ToLower(value))
		if idx := strings.Index(mediaType, ";"); idx != -1 {
			mediaType = strings.TrimSpace(mediaType[:idx])
		}
		if mediaType == "text/event-stream" {
			return true
		}
	}
	return false
}
