package repository

import (
	"context"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/ory/fosite"
)

func TestSQLRepositoryAccessTokenSession(t *testing.T) {
	repo, err := NewSQLRepository("sqlite", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("failed to create sql repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	client := &fosite.DefaultClient{
		ID:           "client-1",
		Secret:       []byte("secret"),
		RedirectURIs: []string{"https://example.com/callback"},
	}

	req := &fosite.Request{
		ID:             "req-1",
		RequestedAt:    time.Now().UTC().Round(time.Second),
		Client:         client,
		RequestedScope: []string{"scope.read"},
		Form:           url.Values{"code": {"value"}},
	}

	if err := repo.CreateAccessTokenSession(ctx, "sig-1", req); err != nil {
		t.Fatalf("CreateAccessTokenSession failed: %v", err)
	}

	result, err := repo.GetAccessTokenSession(ctx, "sig-1", &fosite.DefaultSession{})
	if err != nil {
		t.Fatalf("GetAccessTokenSession failed: %v", err)
	}

	retrievedReq := result.(*fosite.Request)
	if retrievedReq.ID != req.ID {
		t.Fatalf("expected request ID %s, got %s", req.ID, retrievedReq.ID)
	}
	if retrievedReq.Client.GetID() != client.GetID() {
		t.Fatalf("expected client ID %s, got %s", client.GetID(), retrievedReq.Client.GetID())
	}
	if len(retrievedReq.RequestedScope) != 1 || retrievedReq.RequestedScope[0] != "scope.read" {
		t.Fatalf("unexpected requested scope: %#v", retrievedReq.RequestedScope)
	}
}

func TestSQLRepositorySessionPersistence(t *testing.T) {
	repo, err := NewSQLRepository("sqlite", "file::memory:?cache=shared&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("failed to create sql repository: %v", err)
	}
	defer repo.Close()

	sess := &fosite.DefaultSession{
		Username: "test-user",
		Subject:  "test-user",
	}

	ctx := context.Background()
	client := &fosite.DefaultClient{
		ID:           "client-sess",
		Secret:       []byte("secret"),
		RedirectURIs: []string{"https://example.com/callback"},
	}

	req := &fosite.Request{
		ID:             "req-sess",
		RequestedAt:    time.Now().UTC().Round(time.Second),
		Client:         client,
		RequestedScope: []string{"openid"},
		Form:           url.Values{"code": {"value"}},
		Session:        sess,
	}

	if err := repo.CreateAuthorizeCodeSession(ctx, "code-sess", req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession failed: %v", err)
	}

	result, err := repo.GetAuthorizeCodeSession(ctx, "code-sess", &fosite.DefaultSession{})
	if err != nil {
		t.Fatalf("GetAuthorizeCodeSession failed: %v", err)
	}

	restored := result.GetSession().(*fosite.DefaultSession)
	if restored.GetSubject() != "test-user" {
		t.Fatalf("expected subject 'test-user', got '%s'", restored.GetSubject())
	}
	if restored.GetUsername() != "test-user" {
		t.Fatalf("expected username 'test-user', got '%s'", restored.GetUsername())
	}
}

func TestSQLRepositorySessionPersistence_NilSessionStored(t *testing.T) {
	repo, err := NewSQLRepository("sqlite", "file::memory:?cache=shared&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("failed to create sql repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	client := &fosite.DefaultClient{
		ID:           "client-old",
		Secret:       []byte("secret"),
		RedirectURIs: []string{"https://example.com/callback"},
	}

	req := &fosite.Request{
		ID:             "req-old",
		RequestedAt:    time.Now().UTC().Round(time.Second),
		Client:         client,
		RequestedScope: []string{"openid"},
		Form:           url.Values{"code": {"value"}},
	}

	if err := repo.CreateAuthorizeCodeSession(ctx, "code-old", req); err != nil {
		t.Fatalf("CreateAuthorizeCodeSession failed: %v", err)
	}

	result, err := repo.GetAuthorizeCodeSession(ctx, "code-old", &fosite.DefaultSession{})
	if err != nil {
		t.Fatalf("GetAuthorizeCodeSession failed: %v", err)
	}

	if result.GetSession() != nil {
		t.Fatalf("expected nil session when no session was stored, got %v", result.GetSession())
	}
}

func TestSQLRepositoryUnsupportedDriver(t *testing.T) {
	if _, err := NewSQLRepository("unsupported", "dsn"); err == nil {
		t.Fatalf("expected error for unsupported driver but got nil")
	}
}

func TestSQLRepositoryRefreshTokenReuseDetection(t *testing.T) {
	originalGrace := RefreshTokenGracePeriod
	RefreshTokenGracePeriod = 50 * time.Millisecond
	defer func() { RefreshTokenGracePeriod = originalGrace }()

	repo, err := NewSQLRepository("sqlite", "file::memory:?cache=shared&_busy_timeout=5000")
	if err != nil {
		t.Fatalf("failed to create sql repository: %v", err)
	}
	defer repo.Close()

	ctx := context.Background()
	client := &fosite.DefaultClient{
		ID:           "client-rt",
		Secret:       []byte("secret"),
		RedirectURIs: []string{"https://example.com/callback"},
	}

	req := &fosite.Request{
		ID:             "req-rt",
		RequestedAt:    time.Now().UTC().Round(time.Second),
		Client:         client,
		RequestedScope: []string{"openid"},
		Form:           url.Values{"code": {"value"}},
		Session:        &fosite.DefaultSession{Subject: "test-user"},
	}

	if err := repo.CreateRefreshTokenSession(ctx, "sig-rt", "sig-at", req); err != nil {
		t.Fatalf("CreateRefreshTokenSession failed: %v", err)
	}

	// An unrotated refresh token remains usable indefinitely.
	if _, err := repo.GetRefreshTokenSession(ctx, "sig-rt", &fosite.DefaultSession{}); err != nil {
		t.Fatalf("GetRefreshTokenSession (unrotated) failed: %v", err)
	}

	// Rotation keeps the entry: within the grace period the rotated token is
	// still accepted so clients can safely retry a refresh request.
	if err := repo.RotateRefreshToken(ctx, req.ID, "sig-rt"); err != nil {
		t.Fatalf("RotateRefreshToken failed: %v", err)
	}
	if _, err := repo.GetRefreshTokenSession(ctx, "sig-rt", &fosite.DefaultSession{}); err != nil {
		t.Fatalf("GetRefreshTokenSession (rotated, within grace) failed: %v", err)
	}

	// Beyond the grace period the rotated token must report an inactive
	// token so fosite treats the presentation as reuse and revokes the grant.
	time.Sleep(60 * time.Millisecond)
	if _, err := repo.GetRefreshTokenSession(ctx, "sig-rt", &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrInactiveToken) {
		t.Fatalf("expected ErrInactiveToken for rotated token beyond grace, got %v", err)
	}
}
