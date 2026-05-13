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
	UpstreamSessionStorage
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

// UpstreamSession holds the upstream IdP token for a given downstream subject.
// It is used by the revalidation middleware to periodically re-contact the
// IdP (e.g. an OIDC userinfo endpoint) and confirm the user is still
// authorized.
type UpstreamSession struct {
	Subject      string    `json:"subject"`
	Provider     string    `json:"provider"`
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type,omitempty"`
	Expiry       time.Time `json:"expiry"`
	LastChecked  time.Time `json:"last_checked"`
}

// UpstreamSessionStorage persists upstream IdP tokens keyed by the downstream
// subject claim, plus a secondary index from subject to all downstream
// access-token signatures issued for that subject. The index is used to revoke
// every downstream session for a user when upstream revalidation fails
// terminally (e.g. the user was deprovisioned in the IdP).
type UpstreamSessionStorage interface {
	PutUpstreamSession(ctx context.Context, sess *UpstreamSession) error
	GetUpstreamSession(ctx context.Context, subject string) (*UpstreamSession, error)
	DeleteUpstreamSession(ctx context.Context, subject string) error

	IndexAccessTokenForSubject(ctx context.Context, subject, signature string) error
	ListAccessTokensForSubject(ctx context.Context, subject string) ([]string, error)
	UnindexAccessToken(ctx context.Context, subject, signature string) error
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

// subjectFromRequester extracts the OIDC subject from a fosite.Requester by
// inspecting its session. Returns "" if the requester or session is nil, or if
// the session does not implement GetSubject().
func subjectFromRequester(req fosite.Requester) string {
	if req == nil {
		return ""
	}
	sess := req.GetSession()
	if sess == nil {
		return ""
	}
	type subjectGetter interface {
		GetSubject() string
	}
	if sg, ok := sess.(subjectGetter); ok {
		return sg.GetSubject()
	}
	return ""
}

// subjectFromSessionData decodes a serialized fosite session payload and
// extracts the subject claim. Returns "" if decoding fails.
func subjectFromSessionData(data json.RawMessage) string {
	if len(data) == 0 {
		return ""
	}
	var probe struct {
		Subject string `json:"subject"`
	}
	if err := json.Unmarshal(data, &probe); err != nil {
		return ""
	}
	return probe.Subject
}
