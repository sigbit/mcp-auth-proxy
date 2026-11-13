package repository

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ory/fosite"
)

func TestGrantRevocationAndFirstRotation(t *testing.T) {
	for _, backend := range []string{"kvs", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			var repo Repository
			var err error
			if backend == "kvs" {
				repo, err = NewKVSRepository(filepath.Join(t.TempDir(), "test.db"), "test")
			} else {
				repo, err = NewSQLRepository("sqlite", filepath.Join(t.TempDir(), "test.db"))
			}
			if err != nil {
				t.Fatal(err)
			}
			defer repo.Close()
			ctx := context.Background()
			req := &fosite.Request{ID: "grant", Client: &fosite.DefaultClient{ID: "client"}, Session: &fosite.DefaultSession{Subject: "subject"}}
			other := &fosite.Request{ID: "other", Client: req.Client, Session: req.Session}
			for _, entry := range []struct {
				sig string
				req *fosite.Request
			}{{"old", req}, {"replacement", req}, {"other", other}} {
				if err := repo.CreateRefreshTokenSession(ctx, entry.sig, "", entry.req); err != nil {
					t.Fatal(err)
				}
				if err := repo.CreateAccessTokenSession(ctx, entry.sig, entry.req); err != nil {
					t.Fatal(err)
				}
			}
			oldGrace := RefreshTokenGracePeriod
			RefreshTokenGracePeriod = 200 * time.Millisecond
			defer func() { RefreshTokenGracePeriod = oldGrace }()
			if err := repo.RotateRefreshToken(ctx, "grant", "old"); err != nil {
				t.Fatal(err)
			}
			time.Sleep(120 * time.Millisecond)
			if err := repo.RotateRefreshToken(ctx, "grant", "old"); err != nil {
				t.Fatal(err)
			}
			time.Sleep(100 * time.Millisecond)
			got, err := repo.GetRefreshTokenSession(ctx, "old", &fosite.DefaultSession{})
			if !errors.Is(err, fosite.ErrInactiveToken) || got == nil || got.GetID() != "grant" || got.GetSession().GetSubject() != "subject" {
				t.Fatalf("inactive requester: %v, %v", got, err)
			}
			if err := repo.RevokeRefreshToken(ctx, "grant"); err != nil {
				t.Fatal(err)
			}
			if err := repo.RevokeAccessToken(ctx, "grant"); err != nil {
				t.Fatal(err)
			}
			for _, sig := range []string{"old", "replacement"} {
				if _, err := repo.GetRefreshTokenSession(ctx, sig, &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrNotFound) {
					t.Fatalf("refresh %s: %v", sig, err)
				}
				if _, err := repo.GetAccessTokenSession(ctx, sig, &fosite.DefaultSession{}); !errors.Is(err, fosite.ErrNotFound) {
					t.Fatalf("access %s: %v", sig, err)
				}
			}
			if _, err := repo.GetRefreshTokenSession(ctx, "other", &fosite.DefaultSession{}); err != nil {
				t.Fatal(err)
			}
			if _, err := repo.GetAccessTokenSession(ctx, "other", &fosite.DefaultSession{}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
