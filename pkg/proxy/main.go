package proxy

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type ProxyRouter struct {
	externalURL  string
	proxy        http.Handler
	publicKey    *rsa.PublicKey
	proxyHeaders http.Header
}

func NewProxyRouter(
	externalURL string,
	proxy http.Handler,
	publicKey *rsa.PublicKey,
	proxyHeaders http.Header,
) (*ProxyRouter, error) {
	return &ProxyRouter{
		externalURL:  externalURL,
		proxy:        proxy,
		publicKey:    publicKey,
		proxyHeaders: proxyHeaders,
	}, nil
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

	token, err := jwt.Parse(bearerToken, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.publicKey, nil
	})

	if err != nil || !token.Valid {
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
	}

	// Add custom headers to the request
	for name, values := range p.proxyHeaders {
		for _, value := range values {
			c.Request.Header.Add(name, value)
		}
	}

	p.proxy.ServeHTTP(c.Writer, c.Request)
}
