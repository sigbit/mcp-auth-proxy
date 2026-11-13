package repository

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/fosite"
)

func TestKVSRepositoryRefreshTokenReuseDetection(t *testing.T) {
	originalGrace := RefreshTokenGracePeriod
	RefreshTokenGracePeriod = 50 * time.Millisecond
	defer func() { RefreshTokenGracePeriod = originalGrace }()

	path := filepath.Join(t.TempDir(), "kvs.db")
	repo, err := NewKVSRepository(path, "test-bucket")
	if err != nil {
		t.Fatalf("failed to create kvs repository: %v", err)
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
