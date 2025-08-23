//go:generate mockgen -source=interface.go -destination=mock.go -package=auth
package auth

import (
	"context"

	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

type Provider interface {
	Name() string
	Type() string
	RedirectURL() string
	AuthURL() string
	AuthCodeURL(state string) (string, error)
	Exchange(c *gin.Context, state string) (*oauth2.Token, error)
	Authorization(ctx context.Context, token *oauth2.Token) (bool, string, error)
}
