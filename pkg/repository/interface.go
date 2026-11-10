package repository

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ory/fosite"
	"github.com/ory/fosite/handler/oauth2"
	"github.com/ory/fosite/handler/pkce"
)

type Repository interface {
	fosite.Storage
	oauth2.CoreStorage
	oauth2.TokenRevocationStorage
	pkce.PKCERequestStorage
	DynamicClientStorage
	AuthorizeRequestStorage
	Close() error
}

type DynamicClientStorage interface {
	RegisterClient(ctx context.Context, client fosite.Client) error
}

type AuthorizeRequestStorage interface {
	CreateAuthorizeRequest(ctx context.Context, request fosite.AuthorizeRequester) error
	GetAuthorizeRequest(ctx context.Context, requestID string) (fosite.AuthorizeRequester, error)
	DeleteAuthorizeRequest(ctx context.Context, requestID string) error
}

func restoreSession(req *fosite.Request, sessionData json.RawMessage, sess fosite.Session) error {
	if len(sessionData) > 0 && sess != nil {
		if err := json.Unmarshal(sessionData, sess); err != nil {
			return fmt.Errorf("failed to unmarshal session data: %w", err)
		}
		req.SetSession(sess)
	}
	return nil
}

// isRotatedBeyondGracePeriod reports whether a rotated refresh token entry may
// no longer be presented. Rotated entries are kept for RefreshTokenGracePeriod
// so that clients can safely retry a refresh request, e.g. after a network
// failure. Beyond that window, presenting the rotated token is treated as
// reuse: fosite turns the ErrInactiveToken error into grant-wide revocation
// (RFC 6819, section 5.2.2.3).
func isRotatedBeyondGracePeriod(rotatedAt time.Time) bool {
	return !rotatedAt.IsZero() && time.Since(rotatedAt) > RefreshTokenGracePeriod
}
