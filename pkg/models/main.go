package models

import (
	"net/url"
	"time"

	"github.com/ory/fosite"
)

type Request struct {
	ID                string
	RequestedAt       time.Time
	Client            *Client
	RequestedScope    []string
	GrantedScope      []string
	Form              map[string][]string
	RequestedAudience []string
	GrantedAudience   []string
	RotatedAt         time.Time
}

type Client struct {
	ID             string
	Secret         string
	RotatedSecrets []string
	RedirectURIs   []string
	GrantTypes     []string
	ResponseTypes  []string
	Scopes         []string
	Audience       []string
	Public         bool
}

type AuthorizeRequest struct {
	ResponseTypes        []string
	RedirectURI          string
	State                string
	HandledResponseTypes []string
	ResponseMode         string
	DefaultResponseMode  string
	Request              *Request
}

func FromFositeReq(reqester fosite.Requester) *Request {
	req := reqester.(*fosite.Request)
	return &Request{
		ID:                req.ID,
		RequestedAt:       req.RequestedAt,
		Client:            FromFositeClient(req.Client),
		RequestedScope:    req.RequestedScope,
		GrantedScope:      req.GrantedScope,
		Form:              req.Form,
		RequestedAudience: req.RequestedAudience,
		GrantedAudience:   req.GrantedAudience,
	}
}

func (r *Request) ToFositeReq() *fosite.Request {
	return &fosite.Request{
		ID:                r.ID,
		RequestedAt:       r.RequestedAt,
		Client:            r.Client.ToFositeClient(),
		RequestedScope:    r.RequestedScope,
		GrantedScope:      r.GrantedScope,
		Form:              r.Form,
		RequestedAudience: r.RequestedAudience,
		GrantedAudience:   r.GrantedAudience,
	}
}

func FromFositeClient(client fosite.Client) *Client {
	c := client.(*fosite.DefaultClient)

	var rotatedSecrets []string
	for _, rotSecret := range c.RotatedSecrets {
		rotatedSecrets = append(rotatedSecrets, string(rotSecret))
	}

	return &Client{
		ID:             c.ID,
		Secret:         string(c.Secret),
		RotatedSecrets: rotatedSecrets,
		RedirectURIs:   c.RedirectURIs,
		GrantTypes:     c.GrantTypes,
		ResponseTypes:  c.ResponseTypes,
		Scopes:         c.Scopes,
		Audience:       c.Audience,
		Public:         c.Public,
	}
}

func (c *Client) ToFositeClient() *fosite.DefaultClient {
	var rotatedSecrets [][]byte
	for _, rotSecret := range c.RotatedSecrets {
		rotatedSecrets = append(rotatedSecrets, []byte(rotSecret))
	}
	return &fosite.DefaultClient{
		ID:             c.ID,
		Secret:         []byte(c.Secret),
		RotatedSecrets: rotatedSecrets,
		RedirectURIs:   c.RedirectURIs,
		GrantTypes:     c.GrantTypes,
		ResponseTypes:  c.ResponseTypes,
		Scopes:         c.Scopes,
		Audience:       c.Audience,
		Public:         c.Public,
	}
}

func FromFositeAuthorizeRequest(reqester fosite.AuthorizeRequester) *AuthorizeRequest {
	req := reqester.(*fosite.AuthorizeRequest)
	return &AuthorizeRequest{
		ResponseTypes:        req.ResponseTypes,
		RedirectURI:          req.RedirectURI.String(),
		State:                req.State,
		HandledResponseTypes: req.HandledResponseTypes,
		ResponseMode:         string(req.ResponseMode),
		DefaultResponseMode:  string(req.DefaultResponseMode),
		Request:              FromFositeReq(&req.Request),
	}
}

func (ar *AuthorizeRequest) ToFositeAuthorizeRequest() *fosite.AuthorizeRequest {
	return &fosite.AuthorizeRequest{
		ResponseTypes:        ar.ResponseTypes,
		RedirectURI:          Must(url.Parse(ar.RedirectURI)),
		State:                ar.State,
		HandledResponseTypes: ar.HandledResponseTypes,
		ResponseMode:         fosite.ResponseModeType(ar.ResponseMode),
		DefaultResponseMode:  fosite.ResponseModeType(ar.DefaultResponseMode),
		Request:              *ar.Request.ToFositeReq(),
	}
}

func Must[T any](value T, err error) T {
	if err != nil {
		panic(err)
	}
	return value
}
