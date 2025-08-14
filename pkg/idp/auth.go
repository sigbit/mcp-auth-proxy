package idp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/ory/fosite"
	"github.com/ory/fosite/compose"
	"github.com/ory/fosite/token/jwt"
	"github.com/sigbit/mcp-auth-proxy/pkg/repository"
	"github.com/sigbit/mcp-auth-proxy/pkg/utils"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

type IDPRouter struct {
	repo        repository.Repository
	privKey     *rsa.PrivateKey
	logger      *zap.Logger
	externalURL string
	hasher      fosite.Hasher
	provider    fosite.OAuth2Provider
	signer      *jwt.DefaultSigner
}

const Issuer = "mcp-oauth-proxy"

func NewIDPRouter(
	repo repository.Repository,
	privKey *rsa.PrivateKey,
	logger *zap.Logger,
	externalURL string,
	globalSecret string,
) (*IDPRouter, error) {
	var secret []byte
	if globalSecret != "" {
		// hash the global secret for security
		sha256Hash := sha256.Sum256([]byte(globalSecret))
		secret = sha256Hash[:]
	} else {
		logger.Warn("Global secret not provided, generating random secret")
		secret = make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
	}
	hasher := &fosite.BCrypt{
		Config: &fosite.Config{
			HashCost: bcrypt.DefaultCost,
		},
	}
	config := &fosite.Config{
		GlobalSecret:                   secret,
		AccessTokenLifespan:            24 * time.Hour,
		RefreshTokenLifespan:           30 * 24 * time.Hour,
		RefreshTokenScopes:             []string{},
		AccessTokenIssuer:              Issuer,
		EnforcePKCE:                    false,
		EnforcePKCEForPublicClients:    false,
		EnablePKCEPlainChallengeMethod: true,
		ScopeStrategy:                  fosite.HierarchicScopeStrategy,
		MinParameterEntropy:            fosite.MinParameterEntropy,
		ClientSecretsHasher:            hasher,
	}
	provider, signer := customCompose(config, repo, privKey)

	return &IDPRouter{
		repo:        repo,
		privKey:     privKey,
		logger:      logger,
		externalURL: externalURL,
		hasher:      hasher,
		provider:    provider,
		signer:      signer,
	}, nil
}

func customCompose(config *fosite.Config, storage any, key any) (fosite.OAuth2Provider, *jwt.DefaultSigner) {
	keyGetter := func(context.Context) (any, error) { return key, nil }
	signer := &jwt.DefaultSigner{GetPrivateKey: keyGetter}

	provider := compose.Compose(
		config,
		storage,
		&compose.CommonStrategy{
			CoreStrategy:               compose.NewOAuth2JWTStrategy(keyGetter, compose.NewOAuth2HMACStrategy(config), config),
			OpenIDConnectTokenStrategy: compose.NewOpenIDConnectStrategy(keyGetter, config),
			Signer:                     signer,
		},
		compose.OAuth2AuthorizeExplicitFactory,
		compose.OAuth2RefreshTokenGrantFactory,
		compose.OAuth2TokenIntrospectionFactory,
		compose.OAuth2PKCEFactory,
	)
	return provider, signer
}

const (
	AuthorizationEndpoint            = "/idp/auth"
	AuthorizationReturnEndpoint      = "/idp/auth/:ar_id"
	TokenEndpoint                    = "/idp/token"
	IntrospectionEndpoint            = "/idp/introspect"
	RegistrationEndpoint             = "/idp/register"
	OauthAuthorizationServerEndpoint = "/.well-known/oauth-authorization-server"
	JWKSEndpoint                     = "/.well-known/jwks.json"
)

func (a *IDPRouter) SetupRoutes(router gin.IRouter) {
	router.GET(AuthorizationEndpoint, a.handleAuth)
	router.GET(AuthorizationReturnEndpoint, a.handleAuthorizationReturn)
	router.POST(TokenEndpoint, a.handleToken)
	router.POST(IntrospectionEndpoint, a.handleIntrospect)
	router.POST(RegistrationEndpoint, a.handleRegister)
	router.GET(OauthAuthorizationServerEndpoint, a.handleOauthAuthorizationServer)
	router.GET(JWKSEndpoint, a.handleJWKS)
}

func (a *IDPRouter) handleAuth(c *gin.Context) {
	ctx := c.Request.Context()

	ar, err := a.provider.NewAuthorizeRequest(ctx, c.Request)
	if err != nil {
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	if err := a.repo.CreateAuthorizeRequest(ctx, ar); err != nil {
		a.logger.Error("Failed to create authorize requester", zap.Error(err))
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, fosite.ErrServerError.WithWrap(err))
		return
	}
	c.Redirect(302, strings.ReplaceAll(AuthorizationReturnEndpoint, ":ar_id", ar.GetID()))
}

func (a *IDPRouter) handleAuthorizationReturn(c *gin.Context) {
	ctx := c.Request.Context()
	arID := c.Param("ar_id")

	ar, err := a.repo.GetAuthorizeRequest(ctx, arID)
	if err != nil {
		a.logger.Error("Failed to get authorize requester", zap.Error(err))
		c.AbortWithStatusJSON(500, gin.H{"error": "Internal Server Error"})
		return
	}

	for _, scope := range ar.GetRequestedScopes() {
		ar.GrantScope(scope)
	}
	jwtSession, err := NewJWTSessionWithKey(Issuer, "user", a.privKey)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create JWT session", zap.Error(err))
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	response, err := a.provider.NewAuthorizeResponse(ctx, ar, jwtSession)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to generate authorization response", zap.Error(err))
		a.provider.WriteAuthorizeError(ctx, c.Writer, ar, err)
		return
	}

	a.provider.WriteAuthorizeResponse(ctx, c.Writer, ar, response)
}

func (a *IDPRouter) handleToken(c *gin.Context) {
	ctx := c.Request.Context()

	session, err := NewJWTSessionWithKey("", "", a.privKey)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create JWT session for token", zap.Error(err))
		a.provider.WriteAccessError(ctx, c.Writer, nil, fosite.ErrServerError.WithWrap(err))
		return
	}

	accessRequest, err := a.provider.NewAccessRequest(ctx, c.Request, session)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create access request", zap.String("grant_type", c.PostForm("grant_type")))
		a.provider.WriteAccessError(ctx, c.Writer, accessRequest, err)
		return
	}

	response, err := a.provider.NewAccessResponse(ctx, accessRequest)
	if err != nil {
		a.logger.With(utils.Err(err)...).Error("Failed to create access response", zap.String("grant_type", c.PostForm("grant_type")), zap.Error(err))
		a.provider.WriteAccessError(ctx, c.Writer, accessRequest, err)
		return
	}

	a.provider.WriteAccessResponse(ctx, c.Writer, accessRequest, response)
}

func (a *IDPRouter) handleIntrospect(c *gin.Context) {
	ctx := c.Request.Context()
	session, err := NewJWTSessionWithKey("", "", a.privKey)
	if err != nil {
		a.provider.WriteIntrospectionError(ctx, c.Writer, fosite.ErrServerError.WithWrap(err))
		return
	}

	ir, err := a.provider.NewIntrospectionRequest(ctx, c.Request, session)
	if err != nil {
		a.provider.WriteIntrospectionError(ctx, c.Writer, err)
		return
	}

	a.provider.WriteIntrospectionResponse(ctx, c.Writer, ir)
}

type registrationRequest struct {
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	Scope                   string   `json:"scope"`
	RedirectURIs            []string `json:"redirect_uris"`
}

type registrationResponse struct {
	ClientID                string   `json:"client_id"`
	ClientSecret            string   `json:"client_secret,omitempty"`
	RedirectURIs            []string `json:"redirect_uris"`
	ClientName              string   `json:"client_name"`
	GrantTypes              []string `json:"grant_types"`
	ResponseTypes           []string `json:"response_types"`
	TokenEndpointAuthMethod string   `json:"token_endpoint_auth_method"`
	RegistrationClientURI   string   `json:"registration_client_uri"`
	ClientIDIssuedAt        int64    `json:"client_id_issued_at"`
}

func (a *IDPRouter) handleRegister(c *gin.Context) {
	ctx := c.Request.Context()

	var req registrationRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(400, gin.H{"error": "invalid_request", "error_description": err.Error()})
		return
	}

	clientID, err := utils.GenerateClientID()
	if err != nil {
		a.logger.Error("Failed to generate client ID", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	var clientSecret string
	var hashedSecret []byte
	isPublic := req.TokenEndpointAuthMethod == "none"

	if !isPublic {
		// Generate client secret for confidential clients
		clientSecret, err = utils.GenerateClientSecret()
		if err != nil {
			a.logger.Error("Failed to generate client secret", zap.Error(err))
			c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
			return
		}

		hashedSecret, err = a.hasher.Hash(ctx, []byte(clientSecret))
		if err != nil {
			a.logger.Error("Failed to hash client secret", zap.Error(err))
			c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
			return
		}
	}

	client := &fosite.DefaultClient{
		ID:            clientID,
		Secret:        hashedSecret,
		RedirectURIs:  req.RedirectURIs,
		GrantTypes:    req.GrantTypes,
		ResponseTypes: req.ResponseTypes,
		Scopes:        strings.Fields(req.Scope),
		Public:        isPublic,
	}
	if err := a.repo.RegisterClient(ctx, client); err != nil {
		a.logger.Error("Failed to register client", zap.String("client_id", clientID), zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	registrationClientURI, err := url.JoinPath(RegistrationEndpoint, clientID)
	if err != nil {
		a.logger.Error("Failed to create registration client URI", zap.String("client_id", clientID), zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	response := registrationResponse{
		ClientID:                clientID,
		RedirectURIs:            req.RedirectURIs,
		ClientName:              req.ClientName,
		GrantTypes:              req.GrantTypes,
		ResponseTypes:           req.ResponseTypes,
		TokenEndpointAuthMethod: req.TokenEndpointAuthMethod,
		RegistrationClientURI:   registrationClientURI,
		ClientIDIssuedAt:        time.Now().Unix(),
	}

	if !isPublic {
		response.ClientSecret = clientSecret
	}

	c.JSON(201, response)
}

type authorizationServerResponse struct {
	Issuer                            string   `json:"issuer"`
	AuthorizationEndpoint             string   `json:"authorization_endpoint"`
	TokenEndpoint                     string   `json:"token_endpoint"`
	RegistrationEndpoint              string   `json:"registration_endpoint"`
	ScopesSupported                   []string `json:"scopes_supported"`
	ResponseTypesSupported            []string `json:"response_types_supported"`
	ResponseModesSupported            []string `json:"response_modes_supported"`
	GrantTypesSupported               []string `json:"grant_types_supported"`
	TokenEndpointAuthMethodsSupported []string `json:"token_endpoint_auth_methods_supported"`
	CodeChallengeMethodsSupported     []string `json:"code_challenge_methods_supported"`
}

func (a *IDPRouter) handleOauthAuthorizationServer(c *gin.Context) {
	authorizationEndpoint, err := url.JoinPath(a.externalURL, AuthorizationEndpoint)
	if err != nil {
		a.logger.Error("Failed to create authorization endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	tokenEndpoint, err := url.JoinPath(a.externalURL, TokenEndpoint)
	if err != nil {
		a.logger.Error("Failed to create token endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}
	registrationEndpoint, err := url.JoinPath(a.externalURL, RegistrationEndpoint)
	if err != nil {
		a.logger.Error("Failed to create registration endpoint URL", zap.Error(err))
		c.JSON(500, gin.H{"error": "server_error", "error_description": err.Error()})
		return
	}

	res := &authorizationServerResponse{
		Issuer:                            Issuer,
		AuthorizationEndpoint:             authorizationEndpoint,
		TokenEndpoint:                     tokenEndpoint,
		RegistrationEndpoint:              registrationEndpoint,
		ScopesSupported:                   []string{},
		ResponseTypesSupported:            []string{"code"},
		ResponseModesSupported:            []string{"query"},
		GrantTypesSupported:               []string{"authorization_code", "refresh_token"},
		TokenEndpointAuthMethodsSupported: []string{"client_secret_basic", "client_secret_post", "none"},
		CodeChallengeMethodsSupported:     []string{"plain", "S256"},
	}
	c.JSON(200, res)
}

type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type jwks struct {
	Keys []jwk `json:"keys"`
}

func (a *IDPRouter) handleJWKS(c *gin.Context) {
	publicKey := &a.privKey.PublicKey

	// Convert RSA public key components to base64url
	nBytes := publicKey.N.Bytes()
	eBytes := big.NewInt(int64(publicKey.E)).Bytes()

	n := base64.RawURLEncoding.EncodeToString(nBytes)
	e := base64.RawURLEncoding.EncodeToString(eBytes)

	keyID, err := utils.GenerateKeyID(&a.privKey.PublicKey)
	if err != nil {
		a.logger.Error("Failed to generate key ID for JWKS", zap.Error(err))
		c.JSON(500, gin.H{"error": "failed to generate key ID"})
		return
	}

	k := jwk{
		Kty: "RSA",
		Use: "sig",
		Kid: keyID,
		Alg: "RS256",
		N:   n,
		E:   e,
	}

	ks := jwks{Keys: []jwk{k}}
	c.JSON(200, ks)
}

func NewJWTSessionWithKey(iss string, subject string, privateKey *rsa.PrivateKey) (*Session, error) {
	keyID, err := utils.GenerateKeyID(&privateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	return &Session{
		DefaultSession: &fosite.DefaultSession{
			Username: subject,
			Subject:  subject,
		},
		JWTClaims: &jwt.JWTClaims{
			Issuer:    iss,
			Subject:   subject,
			Audience:  []string{},
			ExpiresAt: time.Now().Add(time.Hour),
			IssuedAt:  time.Now(),
			NotBefore: time.Now(),
		},
		JWTHeader: &jwt.Headers{
			Extra: map[string]any{
				"kid": keyID,
			},
		},
	}, nil
}

type Session struct {
	*fosite.DefaultSession
	JWTClaims *jwt.JWTClaims
	JWTHeader *jwt.Headers
}

func (s *Session) GetJWTClaims() jwt.JWTClaimsContainer {
	return s.JWTClaims
}

func (s *Session) GetJWTHeader() *jwt.Headers {
	return s.JWTHeader
}

func (s *Session) Clone() fosite.Session {
	if s == nil {
		return nil
	}

	clone := &Session{
		DefaultSession: &fosite.DefaultSession{
			Username:  s.DefaultSession.Username,
			Subject:   s.DefaultSession.Subject,
			ExpiresAt: s.DefaultSession.ExpiresAt,
		},
		JWTClaims: &jwt.JWTClaims{
			Issuer:    s.JWTClaims.Issuer,
			Subject:   s.JWTClaims.Subject,
			Audience:  s.JWTClaims.Audience,
			ExpiresAt: s.JWTClaims.ExpiresAt,
			IssuedAt:  s.JWTClaims.IssuedAt,
			NotBefore: s.JWTClaims.NotBefore,
		},
		JWTHeader: &jwt.Headers{
			Extra: make(map[string]any),
		},
	}

	for k, v := range s.JWTHeader.Extra {
		clone.JWTHeader.Extra[k] = v
	}

	return clone
}
