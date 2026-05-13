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
	Authorization(ctx context.Context, token *oauth2.Token) (bool, string, map[string]any, error)
}

// Revalidator is an optional interface that providers may implement to support
// periodic upstream re-validation of an existing session. Implementations should
// re-contact the IdP (e.g. an OIDC userinfo endpoint), refresh the upstream
// access token if necessary, and report whether the user is still authorized.
//
// The returned token, if non-nil, supersedes the input token and should be
// persisted by the caller. If err is a FatalRevalidationError, callers MUST
// treat the session as terminated (revoke the downstream token and force the
// user to re-authenticate). All other errors are non-fatal and the existing
// session should be allowed to continue (with a retry on the next interval).
type Revalidator interface {
	Revalidate(ctx context.Context, token *oauth2.Token) (allowed bool, newToken *oauth2.Token, err error)
}

// FatalRevalidationError indicates that revalidation failed in a way that the
// upstream IdP considers terminal (e.g. invalid_grant, invalid_client, 401/403
// from userinfo). Sessions returning this error must be invalidated.
type FatalRevalidationError struct {
	Reason string
	Err    error
}

func (e *FatalRevalidationError) Error() string {
	if e.Err == nil {
		return "fatal revalidation error: " + e.Reason
	}
	return "fatal revalidation error: " + e.Reason + ": " + e.Err.Error()
}

func (e *FatalRevalidationError) Unwrap() error { return e.Err }
