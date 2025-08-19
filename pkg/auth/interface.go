//go:generate mockgen -source=interface.go -destination=mock.go -package=auth
package auth

import (
	"context"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type Provider interface {
	Name() string
	RedirectURL() string
	AuthURL() string
	AuthCodeURL(c *gin.Context, state string) (string, error)
	Exchange(c *gin.Context, state string) (*oauth2.Token, error)
	GetUserID(ctx context.Context, token *oauth2.Token) (string, error)
	Authorization(userid string) (bool, error)
}
