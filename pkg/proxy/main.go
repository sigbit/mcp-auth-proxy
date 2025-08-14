package proxy

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

type ProxyRouter struct {
	externalURL string
}

func NewProxyRouter(
	externalURL string,
) (*ProxyRouter, error) {
	return &ProxyRouter{
		externalURL: externalURL,
	}, nil
}

const (
	OauthProtectedResourceEndpoint = "/.well-known/oauth-protected-resource"
)

func (p *ProxyRouter) SetupRoutes(router gin.IRouter) {
	router.GET(OauthProtectedResourceEndpoint, p.handleProtectedResource)
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
