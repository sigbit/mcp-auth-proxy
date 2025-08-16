package auth

import (
	"context"
	"crypto/sha256"
	"embed"
	"fmt"
	"html/template"
	"net/http"
	"strings"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

//go:embed templates/*
var templateFS embed.FS

type Provider interface {
	Name() string
	RedirectURL() string
	AuthURL() string
	AuthCodeURL(c *gin.Context) (string, error)
	Exchange(c *gin.Context) (*oauth2.Token, error)
	GetUserID(ctx context.Context, token *oauth2.Token) (string, error)
	Authorization(userid string) (bool, error)
}

type AuthRouter struct {
	passswordHash        []string
	providers            map[string]Provider
	template             *template.Template
	unauthorizedTemplate *template.Template
}

func NewAuthRouter(passwordHash []string, providers ...Provider) (*AuthRouter, error) {
	providersMap := make(map[string]Provider)
	for _, provider := range providers {
		providersMap[provider.Name()] = provider
	}

	tmpl, err := template.ParseFS(templateFS, "templates/login.html")
	if err != nil {
		return nil, err
	}

	unauthorizedTmpl, err := template.ParseFS(templateFS, "templates/unauthorized.html")
	if err != nil {
		return nil, err
	}

	return &AuthRouter{
		passswordHash:        passwordHash,
		providers:            providersMap,
		template:             tmpl,
		unauthorizedTemplate: unauthorizedTmpl,
	}, nil
}

const (
	LoginEndpoint          = "/.auth/login"
	LogoutEndpoint         = "/.auth/logout"
	PasswordEndpoint       = "/.auth/password"
	GoogleAuthEndpoint     = "/.auth/google"
	GoogleCallbackEndpoint = "/.auth/google/callback"
	GitHubAuthEndpoint     = "/.auth/github"
	GitHubCallbackEndpoint = "/.auth/github/callback"
)

func (a *AuthRouter) SetupRoutes(router gin.IRouter) {
	router.GET(LoginEndpoint, a.handleLogin)
	router.POST(PasswordEndpoint, a.handlePasswordAuth)
	router.GET(LogoutEndpoint, a.handleLogout)
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

		router.GET(provider.AuthURL(), func(c *gin.Context) {
			url, err := provider.AuthCodeURL(c)
			if err != nil {
				c.Error(err)
				return
			}
			c.Redirect(http.StatusFound, url)
		})
	}
}

type ProviderData struct {
	Name string
	URL  string
}

func (a *AuthRouter) handleLogin(c *gin.Context) {
	var providersData []ProviderData
	for name := range a.providers {
		providersData = append(providersData, ProviderData{
			Name: name,
			URL:  a.providers[name].AuthURL(),
		})
	}

	session := sessions.Default(c)
	passwordError := session.Get("password_error")
	session.Delete("password_error")
	session.Save()

	var passwordErrorStr string
	if passwordError != nil {
		passwordErrorStr = passwordError.(string)
	}

	data := struct {
		Providers     []ProviderData
		HasPassword   bool
		PasswordError string
	}{
		Providers:     providersData,
		HasPassword:   len(a.passswordHash) > 0,
		PasswordError: passwordErrorStr,
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := a.template.Execute(c.Writer, data); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
}

func (a *AuthRouter) handlePasswordAuth(c *gin.Context) {
	password := c.PostForm("password")
	if password == "" {
		session := sessions.Default(c)
		session.Set("password_error", "Password is required")
		session.Save()
		c.Redirect(http.StatusFound, LoginEndpoint)
		return
	}

	hashedPassword := fmt.Sprintf("%x", sha256.Sum256([]byte(password)))

	var isValid bool
	for _, hash := range a.passswordHash {
		if strings.EqualFold(hashedPassword, hash) {
			isValid = true
			break
		}
	}

	if !isValid {
		session := sessions.Default(c)
		session.Set("password_error", "Invalid password")
		session.Save()
		c.Redirect(http.StatusFound, LoginEndpoint)
		return
	}

	session := sessions.Default(c)
	session.Set("provider", "password")
	session.Set("user_id", "password_user")
	session.Save()

	redirectURL := session.Get("redirect_url")
	if redirectURL == nil {
		c.Redirect(http.StatusFound, "/")
		return
	}
	c.Redirect(http.StatusFound, redirectURL.(string))
}

func (a *AuthRouter) handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	session.Clear()
	session.Save()
	c.Redirect(http.StatusFound, LoginEndpoint)
}

func (a *AuthRouter) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		providerName := session.Get("provider")
		userID := session.Get("user_id")
		if providerName == nil || userID == nil {
			session.Set("redirect_url", c.Request.URL.String())
			session.Save()
			c.Redirect(http.StatusFound, LoginEndpoint)
			return
		}

		// Allow password authentication
		if providerName.(string) == "password" {
			c.Next()
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
			data := struct {
				UserID   string
				Provider string
			}{
				UserID:   userID.(string),
				Provider: providerName.(string),
			}
			c.Header("Content-Type", "text/html; charset=utf-8")
			c.Status(http.StatusForbidden)
			if err := a.unauthorizedTemplate.Execute(c.Writer, data); err != nil {
				c.AbortWithError(http.StatusInternalServerError, err)
				return
			}
			c.Abort()
			return
		}
		c.Next()
	}
}
