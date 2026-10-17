package proxy

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mattn/go-jsonpointer"
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
) (*ProxyRouter, error) {
	return &ProxyRouter{
		externalURL:                externalURL,
		proxy:                      proxy,
		publicKey:                  publicKey,
		proxyHeaders:               proxyHeaders,
		httpStreamingOnly:          httpStreamingOnly,
		forwardAuthorizationHeader: forwardAuthorizationHeader,
		headerMapping:              headerMapping,
		headerMappingBase:          headerMappingBase,
	}, nil
}

const (
	OauthProtectedResourceEndpoint = "/.well-known/oauth-protected-resource"
)

func (p *ProxyRouter) SetupRoutes(router gin.IRouter) {
	router.GET(OauthProtectedResourceEndpoint, p.handleProtectedResource)
	router.GET(OauthProtectedResourceEndpoint+"/*resourcePath", p.handleProtectedResourceForPath)
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

func (p *ProxyRouter) handleProtectedResourceForPath(c *gin.Context) {
	resourcePath := strings.Trim(c.Param("resourcePath"), "/")
	if resourcePath == "" {
		p.handleProtectedResource(c)
		return
	}
	c.JSON(http.StatusOK, protectedResourceResponse{
		Resource:             strings.TrimRight(p.externalURL, "/") + "/" + resourcePath,
		AuthorizationServers: []string{p.externalURL},
	})
}

func (p *ProxyRouter) protectedResourceMetadataURL(requestPath string) string {
	metadataURL := strings.TrimRight(p.externalURL, "/") + OauthProtectedResourceEndpoint
	if resourcePath := strings.Trim(requestPath, "/"); resourcePath != "" {
		metadataURL += "/" + resourcePath
	}
	return metadataURL
}

func (p *ProxyRouter) setWWWAuthenticate(c *gin.Context, invalidToken bool) {
	challenge := fmt.Sprintf(`Bearer resource_metadata="%s"`, p.protectedResourceMetadataURL(c.Request.URL.Path))
	if invalidToken {
		challenge += `, error="invalid_token"`
	}
	c.Header("WWW-Authenticate", challenge)
}

func (p *ProxyRouter) handleProxy(c *gin.Context) {
	authHeader := c.Request.Header.Get("Authorization")
	if !strings.HasPrefix(authHeader, "Bearer ") {
		p.setWWWAuthenticate(c, false)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}
	bearerToken := strings.TrimPrefix(authHeader, "Bearer ")

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(bearerToken, claims, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return p.publicKey, nil
	}, jwt.WithIssuer(p.externalURL), jwt.WithAudience(p.externalURL))

	if err != nil || !token.Valid {
		p.setWWWAuthenticate(c, true)
		c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
		return
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

func isSSEGetRequest(r *http.Request) bool {
	if r.Method != http.MethodGet {
		return false
	}
	accept := r.Header.Get("Accept")
	if accept == "" {
		return false
	}
	for _, value := range strings.Split(accept, ",") {
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
