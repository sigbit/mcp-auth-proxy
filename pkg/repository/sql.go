package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/ory/fosite"
	"github.com/sigbit/mcp-auth-proxy/pkg/models"
	"gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

type sqlRepository struct {
	db *gorm.DB
}

type authorizeCodeSession struct {
	Code      string `gorm:"primaryKey;size:255"`
	Request   []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type accessTokenSession struct {
	Signature string `gorm:"primaryKey;size:255"`
	Request   []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type refreshTokenSession struct {
	Signature       string `gorm:"primaryKey;size:255"`
	AccessSignature string `gorm:"size:255"`
	Request         []byte `gorm:"not null"`
	CreatedAt       time.Time
	UpdatedAt       time.Time
}

type clientRecord struct {
	ID        string `gorm:"primaryKey;size:255"`
	Client    []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type pkceRequestSession struct {
	Signature string `gorm:"primaryKey;size:255"`
	Request   []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

type authorizeRequestRecord struct {
	RequestID string `gorm:"primaryKey;size:255"`
	Request   []byte `gorm:"not null"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

func NewSQLRepository(driver string, dsn string) (Repository, error) {
	if driver == "" {
		return nil, fmt.Errorf("driver must not be empty")
	}
	if dsn == "" {
		return nil, fmt.Errorf("dsn must not be empty")
	}

	var dialector gorm.Dialector
	switch strings.ToLower(driver) {
	case "sqlite":
		dialector = sqlite.Open(dsn)
	case "postgres", "postgresql":
		dialector = postgres.Open(dsn)
	case "mysql":
		dialector = mysql.Open(dsn)
	default:
		return nil, fmt.Errorf("unsupported driver: %s", driver)
	}

	db, err := gorm.Open(dialector, &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("failed to connect database: %w", err)
	}

	if err := db.AutoMigrate(
		&authorizeCodeSession{},
		&accessTokenSession{},
		&refreshTokenSession{},
		&clientRecord{},
		&pkceRequestSession{},
		&authorizeRequestRecord{},
	); err != nil {
		return nil, fmt.Errorf("failed to migrate schema: %w", err)
	}

	return &sqlRepository{db: db}, nil
}

func (r *sqlRepository) CreateAuthorizeCodeSession(ctx context.Context, code string, fositeReq fosite.Requester) error {
	data, err := marshalRequest(fositeReq)
	if err != nil {
		return err
	}

	session := authorizeCodeSession{
		Code:    code,
		Request: data,
	}

	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&session).Error
}

func (r *sqlRepository) GetAuthorizeCodeSession(ctx context.Context, code string, sess fosite.Session) (fosite.Requester, error) {
	var session authorizeCodeSession
	if err := r.db.WithContext(ctx).First(&session, "code = ?", code).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load authorize code session: %w", err)
	}

	return unmarshalRequest(session.Request, sess)
}

func (r *sqlRepository) InvalidateAuthorizeCodeSession(ctx context.Context, code string) error {
	return r.db.WithContext(ctx).Delete(&authorizeCodeSession{}, "code = ?", code).Error
}

func (r *sqlRepository) CreateAccessTokenSession(ctx context.Context, signature string, fositeReq fosite.Requester) error {
	data, err := marshalRequest(fositeReq)
	if err != nil {
		return err
	}

	session := accessTokenSession{
		Signature: signature,
		Request:   data,
	}

	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&session).Error
}

func (r *sqlRepository) GetAccessTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var session accessTokenSession
	if err := r.db.WithContext(ctx).First(&session, "signature = ?", signature).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load access token session: %w", err)
	}

	return unmarshalRequest(session.Request, sess)
}

func (r *sqlRepository) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return r.db.WithContext(ctx).Delete(&accessTokenSession{}, "signature = ?", signature).Error
}

func (r *sqlRepository) CreateRefreshTokenSession(ctx context.Context, signature string, accessSignature string, req fosite.Requester) error {
	data, err := marshalRequest(req)
	if err != nil {
		return err
	}

	session := refreshTokenSession{
		Signature:       signature,
		AccessSignature: accessSignature,
		Request:         data,
	}

	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&session).Error
}

func (r *sqlRepository) GetRefreshTokenSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var session refreshTokenSession
	if err := r.db.WithContext(ctx).First(&session, "signature = ?", signature).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load refresh token session: %w", err)
	}

	return unmarshalRequest(session.Request, sess)
}

func (r *sqlRepository) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return r.db.WithContext(ctx).Delete(&refreshTokenSession{}, "signature = ?", signature).Error
}

func (r *sqlRepository) RotateRefreshToken(ctx context.Context, requestID string, signature string) error {
	var session refreshTokenSession
	if err := r.db.WithContext(ctx).First(&session, "signature = ?", signature).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return fosite.ErrNotFound
		}
		return fmt.Errorf("failed to load refresh token session: %w", err)
	}

	var req models.Request
	if err := json.Unmarshal(session.Request, &req); err != nil {
		return fmt.Errorf("failed to decode refresh token session: %w", err)
	}
	req.RotatedAt = time.Now().UTC()

	data, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to encode refresh token session: %w", err)
	}

	return r.db.WithContext(ctx).
		Model(&refreshTokenSession{}).
		Where("signature = ?", signature).
		Update("request", data).Error
}

func (r *sqlRepository) RevokeRefreshToken(ctx context.Context, requestID string) error {
	return r.db.WithContext(ctx).Delete(&refreshTokenSession{}, "signature = ?", requestID).Error
}

func (r *sqlRepository) RevokeAccessToken(ctx context.Context, requestID string) error {
	return r.db.WithContext(ctx).Delete(&accessTokenSession{}, "signature = ?", requestID).Error
}

func (r *sqlRepository) RegisterClient(ctx context.Context, fositeClient fosite.Client) error {
	data, err := marshalClient(fositeClient)
	if err != nil {
		return err
	}

	record := clientRecord{
		ID:     fositeClient.GetID(),
		Client: data,
	}

	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&record).Error
}

func (r *sqlRepository) GetClient(ctx context.Context, id string) (fosite.Client, error) {
	var record clientRecord
	if err := r.db.WithContext(ctx).First(&record, "id = ?", id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load client: %w", err)
	}

	return unmarshalClient(record.Client)
}

func (r *sqlRepository) ClientAssertionJWTValid(ctx context.Context, jti string) error {
	return errors.New("not implemented")
}

func (r *sqlRepository) SetClientAssertionJWT(ctx context.Context, jti string, exp time.Time) error {
	return errors.New("not implemented")
}

func (r *sqlRepository) CreatePKCERequestSession(ctx context.Context, signature string, req fosite.Requester) error {
	data, err := marshalRequest(req)
	if err != nil {
		return err
	}

	session := pkceRequestSession{
		Signature: signature,
		Request:   data,
	}

	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&session).Error
}

func (r *sqlRepository) GetPKCERequestSession(ctx context.Context, signature string, sess fosite.Session) (fosite.Requester, error) {
	var session pkceRequestSession
	if err := r.db.WithContext(ctx).First(&session, "signature = ?", signature).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load pkce request session: %w", err)
	}

	return unmarshalRequest(session.Request, sess)
}

func (r *sqlRepository) DeletePKCERequestSession(ctx context.Context, signature string) error {
	return r.db.WithContext(ctx).Delete(&pkceRequestSession{}, "signature = ?", signature).Error
}

func (r *sqlRepository) CreateAuthorizeRequest(ctx context.Context, fositeAR fosite.AuthorizeRequester) error {
	data, err := marshalAuthorizeRequest(fositeAR)
	if err != nil {
		return err
	}

	record := authorizeRequestRecord{
		RequestID: fositeAR.GetID(),
		Request:   data,
	}

	return r.db.WithContext(ctx).
		Clauses(clause.OnConflict{UpdateAll: true}).
		Create(&record).Error
}

func (r *sqlRepository) GetAuthorizeRequest(ctx context.Context, requestID string) (fosite.AuthorizeRequester, error) {
	var record authorizeRequestRecord
	if err := r.db.WithContext(ctx).First(&record, "request_id = ?", requestID).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, fosite.ErrNotFound
		}
		return nil, fmt.Errorf("failed to load authorize request: %w", err)
	}

	return unmarshalAuthorizeRequest(record.Request)
}

func (r *sqlRepository) DeleteAuthorizeRequest(ctx context.Context, requestID string) error {
	return r.db.WithContext(ctx).Delete(&authorizeRequestRecord{}, "request_id = ?", requestID).Error
}

func (r *sqlRepository) Close() error {
	sqlDB, err := r.db.DB()
	if err != nil {
		return fmt.Errorf("failed to get sql db: %w", err)
	}
	return sqlDB.Close()
}

func marshalRequest(req fosite.Requester) ([]byte, error) {
	data, err := json.Marshal(models.FromFositeReq(req))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}
	return data, nil
}

func unmarshalRequest(data []byte, sess fosite.Session) (fosite.Requester, error) {
	var req models.Request
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal request: %w", err)
	}
	fositeReq := req.ToFositeReq()
	if sess != nil {
		fositeReq.SetSession(sess)
	}
	return fositeReq, nil
}

func marshalClient(client fosite.Client) ([]byte, error) {
	data, err := json.Marshal(models.FromFositeClient(client))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal client: %w", err)
	}
	return data, nil
}

func unmarshalClient(data []byte) (fosite.Client, error) {
	var client models.Client
	if err := json.Unmarshal(data, &client); err != nil {
		return nil, fmt.Errorf("failed to unmarshal client: %w", err)
	}
	return client.ToFositeClient(), nil
}

func marshalAuthorizeRequest(req fosite.AuthorizeRequester) ([]byte, error) {
	data, err := json.Marshal(models.FromFositeAuthorizeRequest(req))
	if err != nil {
		return nil, fmt.Errorf("failed to marshal authorize request: %w", err)
	}
	return data, nil
}

func unmarshalAuthorizeRequest(data []byte) (fosite.AuthorizeRequester, error) {
	var req models.AuthorizeRequest
	if err := json.Unmarshal(data, &req); err != nil {
		return nil, fmt.Errorf("failed to unmarshal authorize request: %w", err)
	}
	return req.ToFositeAuthorizeRequest(), nil
}
