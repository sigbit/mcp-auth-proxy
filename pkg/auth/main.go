package auth

import (
	"context"
	"embed"
	"html/template"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

//go:embed templates/*
var templateFS embed.FS

type Provider interface {
	Name() string
	RedirectURL() string
	AuthCodeURL(c *gin.Context) (string, error)
	Exchange(c *gin.Context) (*oauth2.Token, error)
	GetUserID(ctx context.Context, token *oauth2.Token) (string, error)
	Authorization(userid string) (bool, error)
}

type AuthRouter struct {
	providers map[string]Provider
	template  *template.Template
}

func NewAuthRouter(providers ...Provider) (*AuthRouter, error) {
	providersMap := make(map[string]Provider)
	for _, provider := range providers {
		providersMap[provider.Name()] = provider
	}

	tmpl, err := template.ParseFS(templateFS, "templates/login.html")
	if err != nil {
		return nil, err
	}

	return &AuthRouter{
		providers: providersMap,
		template:  tmpl,
	}, nil
}

const (
	LoginEndpoint          = "/.auth/login"
	GoogleCallbackEndpoint = "/.auth/google/callback"
	GithubCallbackEndpoint = "/.auth/github/callback"
)

func (a *AuthRouter) SetupRoutes(router gin.IRouter) {
	router.GET(LoginEndpoint, a.handleLogin)
	for providerName, provider := range a.providers {
		router.GET(provider.RedirectURL(), func(c *gin.Context) {
			session := sessions.Default(c)

			token, err := provider.Exchange(c)
			if err != nil {
				c.Error(err)
				return
			}
			userID, err := provider.GetUserID(c, token)
			if err != nil {
				c.Error(err)
				return
			}
			session.Set("provider", providerName)
			session.Set("user_id", userID)
			session.Save()
			redirectURL := session.Get("redirect_url")
			c.Redirect(http.StatusFound, redirectURL.(string))
		})
	}
}

type ProviderData struct {
	Name        string
	DisplayName string
}

func (a *AuthRouter) handleLogin(c *gin.Context) {
	var providersData []ProviderData
	for name := range a.providers {
		providersData = append(providersData, ProviderData{
			Name:        name,
			DisplayName: name,
		})
	}

	data := struct {
		Providers []ProviderData
	}{
		Providers: providersData,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := a.template.Execute(c.Writer, data); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
}

func (a *AuthRouter) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		providerName := session.Get("provider")
		userID := session.Get("user_id")
		if providerName == nil || userID == nil {
			c.Redirect(http.StatusFound, LoginEndpoint)
			return
		}
		p, ok := a.providers[providerName.(string)]
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unknown provider"})
			return
		}
		ok, err := p.Authorization(userID.(string))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed"})
			return
		}
		if !ok {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "Unauthorized"})
			return
		}
		c.Next()
	}
}
