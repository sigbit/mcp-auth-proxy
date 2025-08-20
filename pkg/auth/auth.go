package auth

import (
	"embed"
	"errors"
	"html/template"
	"net/http"

	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"github.com/sigbit/mcp-auth-proxy/pkg/utils"
	"golang.org/x/crypto/bcrypt"
)

//go:embed templates/*
var templateFS embed.FS

type AuthRouter struct {
	passwordHash         []string
	providers            []Provider
	loginTemplate        *template.Template
	unauthorizedTemplate *template.Template
	errorTemplate        *template.Template
}

func NewAuthRouter(passwordHash []string, providers ...Provider) (*AuthRouter, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/login.html")
	if err != nil {
		return nil, err
	}

	unauthorizedTmpl, err := template.ParseFS(templateFS, "templates/unauthorized.html")
	if err != nil {
		return nil, err
	}

	errorTmpl, err := template.ParseFS(templateFS, "templates/error.html")
	if err != nil {
		return nil, err
	}

	return &AuthRouter{
		passwordHash:         passwordHash,
		providers:            providers,
		loginTemplate:        tmpl,
		unauthorizedTemplate: unauthorizedTmpl,
		errorTemplate:        errorTmpl,
	}, nil
}

const (
	LoginEndpoint          = "/.auth/login"
	LogoutEndpoint         = "/.auth/logout"
	GoogleAuthEndpoint     = "/.auth/google"
	GoogleCallbackEndpoint = "/.auth/google/callback"
	GitHubAuthEndpoint     = "/.auth/github"
	GitHubCallbackEndpoint = "/.auth/github/callback"
	OIDCAuthEndpoint       = "/.auth/oidc"
	OIDCCallbackEndpoint   = "/.auth/oidc/callback"

	PasswordProvider = "password"
	PasswordUserID   = "password_user"

	SessionKeyProvider    = "provider"
	SessionKeyUserID      = "user_id"
	SessionKeyRedirectURL = "redirect_url"
	SessionKeyOAuthState  = "oauth_state"
)

func (a *AuthRouter) SetupRoutes(router gin.IRouter) {
	router.GET(LoginEndpoint, a.handleLogin)
	router.POST(LoginEndpoint, a.handleLoginPost)
	router.GET(LogoutEndpoint, a.handleLogout)
	for _, provider := range a.providers {
		router.GET(provider.RedirectURL(), func(c *gin.Context) {
			session := sessions.Default(c)
			state := session.Get(SessionKeyOAuthState)
			if state == nil {
				a.renderError(c, errors.New("OAuth state is missing"))
				return
			}
			token, err := provider.Exchange(c, state.(string))
			if err != nil {
				a.renderError(c, err)
				return
			}
			userID, err := provider.GetUserID(c, token)
			if err != nil {
				a.renderError(c, err)
				return
			}
			ok, err := provider.Authorization(userID)
			if err != nil {
				a.renderError(c, err)
				return
			}
			if !ok {
				a.renderUnauthorized(c, userID, provider.Name())
				return
			}
			session.Set(SessionKeyProvider, provider.Name())
			session.Set(SessionKeyUserID, userID)
			redirectURL := session.Get(SessionKeyRedirectURL)
			if redirectURL != nil {
				session.Delete(SessionKeyRedirectURL)
			}
			if err := session.Save(); err != nil {
				a.renderError(c, err)
				return
			}

			if redirectURL == nil {
				c.Redirect(http.StatusFound, "/")
			} else {
				c.Redirect(http.StatusFound, redirectURL.(string))
			}
		})

		router.GET(provider.AuthURL(), func(c *gin.Context) {
			session := sessions.Default(c)

			state, err := utils.GenerateState()
			if err != nil {
				a.renderError(c, err)
				return
			}
			url, err := provider.AuthCodeURL(c, state)
			if err != nil {
				a.renderError(c, err)
				return
			}
			session.Set(SessionKeyOAuthState, state)
			if err := session.Save(); err != nil {
				a.renderError(c, err)
				return
			}
			c.Redirect(http.StatusFound, url)
		})
	}
}

func (a *AuthRouter) getProvider(name string) Provider {
	for _, provider := range a.providers {
		if provider.Name() == name {
			return provider
		}
	}
	return nil
}

func (a *AuthRouter) handleLogin(c *gin.Context) {
	if c.Request.Method == "POST" {
		a.handleLoginPost(c)
		return
	}
	a.renderLogin(c, "")
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
		a.renderLogin(c, errorMessage)
		return
	}

	session := sessions.Default(c)
	session.Set(SessionKeyProvider, PasswordProvider)
	session.Set(SessionKeyUserID, PasswordUserID)
	redirectURL := session.Get(SessionKeyRedirectURL)
	if redirectURL != nil {
		session.Delete(SessionKeyRedirectURL)
	}
	if err := session.Save(); err != nil {
		a.renderError(c, err)
		return
	}

	if redirectURL == nil {
		c.Redirect(http.StatusFound, "/")
	} else {
		c.Redirect(http.StatusFound, redirectURL.(string))
	}
}

func (a *AuthRouter) handleLogout(c *gin.Context) {
	session := sessions.Default(c)
	session.Delete(SessionKeyProvider)
	session.Delete(SessionKeyUserID)
	if err := session.Save(); err != nil {
		a.renderError(c, err)
		return
	}
	c.Redirect(http.StatusFound, LoginEndpoint)
}

func (a *AuthRouter) RequireAuth() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		providerName := session.Get(SessionKeyProvider)
		userID := session.Get(SessionKeyUserID)
		if providerName == nil || userID == nil {
			session.Set(SessionKeyRedirectURL, c.Request.URL.String())
			if err := session.Save(); err != nil {
				a.renderError(c, err)
				return
			}
			c.Redirect(http.StatusFound, LoginEndpoint)
			return
		}

		// Allow password authentication
		if providerName.(string) == PasswordProvider {
			c.Next()
			return
		}

		p := a.getProvider(providerName.(string))
		if p == nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Unknown provider"})
			return
		}
		ok, err := p.Authorization(userID.(string))
		if err != nil {
			c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"error": "Authorization failed"})
			return
		}
		if !ok {
			a.renderUnauthorized(c, userID.(string), providerName.(string))
			c.Abort()
			return
		}
		c.Next()
	}
}

type loginTemplateData struct {
	Providers     []Provider
	HasPassword   bool
	PasswordError string
}

type unauthorizedTemplateData struct {
	UserID   string
	Provider string
}

type errorTemplateData struct {
	ErrorMessage string
}

func (a *AuthRouter) renderLogin(c *gin.Context, passwordError string) {
	data := loginTemplateData{
		Providers:     a.providers,
		HasPassword:   len(a.passwordHash) > 0,
		PasswordError: passwordError,
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	if passwordError != "" {
		c.Status(http.StatusBadRequest)
	} else {
		c.Status(http.StatusOK)
	}
	if err := a.loginTemplate.Execute(c.Writer, data); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
}

func (a *AuthRouter) renderUnauthorized(c *gin.Context, userID, providerName string) {
	data := unauthorizedTemplateData{
		UserID:   userID,
		Provider: providerName,
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusForbidden)
	if err := a.unauthorizedTemplate.Execute(c.Writer, data); err != nil {
		c.AbortWithError(http.StatusInternalServerError, err)
		return
	}
}

func (a *AuthRouter) renderError(c *gin.Context, err error) {
	data := errorTemplateData{
		ErrorMessage: err.Error(),
	}
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.Status(http.StatusInternalServerError)
	if templateErr := a.errorTemplate.Execute(c.Writer, data); templateErr != nil {
		c.AbortWithError(http.StatusInternalServerError, templateErr)
		return
	}
	c.Abort()
}
