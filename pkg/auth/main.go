package auth

import (
	"context"
	"embed"
	"html/template"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
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
	passwordHash         []string
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
		passwordHash:         passwordHash,
		providers:            providersMap,
		template:             tmpl,
		unauthorizedTemplate: unauthorizedTmpl,
	}, nil
}

const (
	LoginEndpoint          = "/.auth/login"
	LogoutEndpoint         = "/.auth/logout"
	GoogleAuthEndpoint     = "/.auth/google"
	GoogleCallbackEndpoint = "/.auth/google/callback"
	GitHubAuthEndpoint     = "/.auth/github"
	GitHubCallbackEndpoint = "/.auth/github/callback"
	
	PasswordProvider = "password"
	PasswordUserID   = "password_user"
)

func (a *AuthRouter) SetupRoutes(router gin.IRouter) {
	router.GET(LoginEndpoint, a.handleLogin)
	router.POST(LoginEndpoint, a.handleLoginPost)
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
	if c.Request.Method == "POST" {
		a.handleLoginPost(c)
		return
	}

	var providersData []ProviderData
	for name := range a.providers {
		providersData = append(providersData, ProviderData{
			Name: name,
			URL:  a.providers[name].AuthURL(),
		})
	}

	data := struct {
		Providers     []ProviderData
		HasPassword   bool
		PasswordError string
	}{
		Providers:     providersData,
		HasPassword:   len(a.passwordHash) > 0,
		PasswordError: "",
	}

	c.Header("Content-Type", "text/html; charset=utf-8")
	if err := a.template.Execute(c.Writer, data); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
}

func (a *AuthRouter) handleLoginPost(c *gin.Context) {
	password := c.PostForm("password")
	var errorMessage string

	if password == "" {
		errorMessage = "Password is required"
	} else {
		var isValid bool
		for _, hash := range a.passwordHash {
			err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
			if err == nil {
				isValid = true
				break
			}
		}

		if !isValid {
			errorMessage = "Invalid password"
		}
	}

	if errorMessage != "" {
		var providersData []ProviderData
		for name := range a.providers {
			providersData = append(providersData, ProviderData{
				Name: name,
				URL:  a.providers[name].AuthURL(),
			})
		}

		data := struct {
			Providers     []ProviderData
			HasPassword   bool
			PasswordError string
		}{
			Providers:     providersData,
			HasPassword:   len(a.passwordHash) > 0,
			PasswordError: errorMessage,
		}

		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Status(http.StatusBadRequest)
		if err := a.template.Execute(c.Writer, data); err != nil {
			c.AbortWithError(http.StatusInternalServerError, err)
			return
		}
		return
	}

	session := sessions.Default(c)
	session.Set("provider", PasswordProvider)
	session.Set("user_id", PasswordUserID)
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
	c.String(http.StatusOK, "Logged out")
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
		if providerName.(string) == PasswordProvider {
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
