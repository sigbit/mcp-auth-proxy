package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	time "time"

	"github.com/ory/fosite"
	"github.com/sigbit/mcp-auth-proxy/pkg/models"
	"go.etcd.io/bbolt"
)

type kvsRepository struct {
	db         *bbolt.DB
	bucketName string
}

var RefreshTokenGracePeriod = 1 * time.Hour

func NewKVSRepository(path string, bucketName string) (Repository, error) {
	db, err := bbolt.Open(path, 0600, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}
	if err := db.Update(func(tx *bbolt.Tx) error {
		_, err := tx.CreateBucketIfNotExists([]byte(bucketName))
		return err
	}); err != nil {
		return nil, fmt.Errorf("failed to create bucket: %w", err)
	}
	return &kvsRepository{
		db:         db,
		bucketName: bucketName,
	}, nil
}

func (r *kvsRepository) create(ctx context.Context, key string, value any) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
		return bucket.Put([]byte(key), data)
	})
}

func (r *kvsRepository) get(ctx context.Context, key string, value any) error {
	return r.db.View(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		data := bucket.Get([]byte(key))
		if data == nil {
			return fmt.Errorf("key %q not found", key)
		}
		return json.Unmarshal(data, value)
	})
}

func (r *kvsRepository) delete(ctx context.Context, key string) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket %q not found", r.bucketName)
		}
		return bucket.Delete([]byte(key))
	})
}

func (r *kvsRepository) update(ctx context.Context, key string, value any) error {
	return r.db.Update(func(tx *bbolt.Tx) error {
		bucket := tx.Bucket([]byte(r.bucketName))
		if bucket == nil {
			return fmt.Errorf("bucket %q not found", r.bucketName)
		}
		data, err := json.Marshal(value)
		if err != nil {
			return fmt.Errorf("failed to marshal value: %w", err)
		}
		return bucket.Put([]byte(key), data)
	})
}

func (r *kvsRepository) CreateAuthorizeCodeSession(ctx context.Context, code string, fositeReq fosite.Requester) error {
	return r.create(ctx, "authorize_code-"+code, models.FromFositeReq(fositeReq))
}

func (r *kvsRepository) GetAuthorizeCodeSession(ctx context.Context, code string, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := r.get(ctx, "authorize_code-"+code, &req); err != nil {
		return nil, err
	}
	fositeReq := req.ToFositeReq()
	fositeReq.SetSession(sess)
	return fositeReq, nil
}

func (r *kvsRepository) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return r.delete(ctx, "authorize_code-"+code)
}

func (r *kvsRepository) CreateAccessTokenSession(ctx context.Context, signature string, fositeReq fosite.Requester) error {
	return r.create(ctx, "access_token-"+signature, models.FromFositeReq(fositeReq))
}

func (r *kvsRepository) GetAccessTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := r.get(ctx, "access_token-"+signature, &req); err != nil {
		return nil, err
	}
	fositeReq := req.ToFositeReq()
	fositeReq.SetSession(sess)
	return fositeReq, nil
}

func (r *kvsRepository) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return r.delete(ctx, "access_token-"+signature)
}

func (r *kvsRepository) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, req fosite.Requester) (err error) {
	return r.create(ctx, "refresh_token-"+signature, models.FromFositeReq(req))
}

func (r *kvsRepository) GetRefreshTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := r.get(ctx, "refresh_token-"+signature, &req); err != nil {
		return nil, err
	}
	fositeReq := req.ToFositeReq()
	fositeReq.SetSession(sess)
	return fositeReq, nil
}

func (r *kvsRepository) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return r.delete(ctx, "refresh_token-"+signature)
}

func (r *kvsRepository) RotateRefreshToken(ctx context.Context, requestID string, signature string) error {
	var req models.Request
	if err := r.get(ctx, "refresh_token-"+signature, &req); err != nil {
		return err
	}
	req.RotatedAt = time.Now()
	return r.update(ctx, "refresh_token-"+signature, req)
}

// RevokeRefreshToken revokes a refresh token as specified in:
// https://tools.ietf.org/html/rfc7009#section-2.1
// If the particular
// token is a refresh token and the authorization server supports the
// revocation of access tokens, then the authorization server SHOULD
// also invalidate all access tokens based on the same authorization
// grant (see Implementation Note).
func (r *kvsRepository) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return r.delete(ctx, "refresh_token-"+requestID)
}

// RevokeAccessToken revokes an access token as specified in:
// https://tools.ietf.org/html/rfc7009#section-2.1
// If the token passed to the request
// is an access token, the server MAY revoke the respective refresh
// token as well.
func (r *kvsRepository) RevokeAccessToken(ctx context.Context, requestID string) error {
	return r.delete(ctx, "access_token-"+requestID)
}

func (r *kvsRepository) RegisterClient(ctx context.Context, fositeClient fosite.Client) error {
	return r.create(ctx, "client-"+fositeClient.GetID(), models.FromFositeClient(fositeClient))
}

// GetClient loads the client by its ID or returns an error
// if the client does not exist or another error occurred.
func (r *kvsRepository) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var client models.Client
	if err := r.get(ctx, "client-"+id, &client); err != nil {
		return nil, err
	}
	return client.ToFositeClient(), nil
}

// ClientAssertionJWTValid returns an error if the JTI is
// known or the DB check failed and nil if the JTI is not known.
func (r *kvsRepository) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return errors.New("not implemented")
}

// SetClientAssertionJWT marks a JTI as known for the given
// expiry time. Before inserting the new JTI, it will clean
// up any existing JTIs that have expired as those tokens can
// not be replayed due to the expiry.
func (r *kvsRepository) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return errors.New("not implemented")
}

func (r *kvsRepository) CreatePKCERequestSession(ctx context.Context, signature string, req fosite.Requester) error {
	return r.create(ctx, "pkce_request-"+signature, models.FromFositeReq(req))
}

func (r *kvsRepository) GetPKCERequestSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := r.get(ctx, "pkce_request-"+signature, &req); err != nil {
		return nil, err
	}
	fositeReq := req.ToFositeReq()
	fositeReq.SetSession(sess)
	return fositeReq, nil
}

func (r *kvsRepository) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return r.delete(ctx, "pkce_request-"+signature)
}

func (r *kvsRepository) CreateAuthorizeRequest(ctx context.Context, fositeAR fosite.AuthorizeRequester) error {
	return r.create(ctx, "authorize_request-"+fositeAR.GetID(), models.FromFositeAuthorizeRequest(fositeAR))
}

func (r *kvsRepository) GetAuthorizeRequest(ctx context.Context, requestID string) (fosite.AuthorizeRequester, error) {
	var ar models.AuthorizeRequest
	if err := r.get(ctx, "authorize_request-"+requestID, &ar); err != nil {
		return nil, err
	}
	return ar.ToFositeAuthorizeRequest(), nil
}

func (r *kvsRepository) DeleteAuthorizeRequest(ctx context.Context, requestID string) error {
	return r.delete(ctx, "authorize_request-"+requestID)
}

func (r *kvsRepository) Close() error {
	return r.db.Close()
}
