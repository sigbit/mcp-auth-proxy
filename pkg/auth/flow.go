package auth

import (
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/securecookie"
)

// FlowMaxAge bounds how long an unfinished login or authorization request
// stays valid, in seconds. It matches the session cookie.
const FlowMaxAge = 600

const (
	oauthFlowPrefix     = "oauth_"
	authorizeFlowPrefix = "idp_ar_"
)

var flowIDPattern = regexp.MustCompile(`^[A-Za-z0-9-]{1,64}$`)

// FlowCookies keeps the state of each in-flight login or authorization
// request in a cookie of its own, named after the flow.
//
// The alternative, one shared session cookie holding every flow's state,
// breaks as soon as a client opens several flows at once: each response
// rewrites the whole cookie, the browser keeps only the last, and every
// other flow fails its state check. Claude's desktop app does exactly that,
// starting one flow per configured MCP server at the same moment. With one
// cookie per flow, concurrent flows never write to the same cookie.
//
// Values are HMAC-signed, and the cookie name is covered by the signature, so
// a cookie issued for one flow cannot be replayed as another's.
type FlowCookies struct {
	codec  *securecookie.SecureCookie
	secure bool
}

func NewFlowCookies(secret []byte, secure bool) *FlowCookies {
	codec := securecookie.New(secret, nil)
	codec.MaxAge(FlowMaxAge)
	return &FlowCookies{codec: codec, secure: secure}
}

// Set starts tracking flow id under prefix, remembering value with it.
func (f *FlowCookies) Set(c *gin.Context, prefix, id, value string) error {
	if !flowIDPattern.MatchString(id) {
		return errInvalidFlowID
	}
	encoded, err := f.codec.Encode(prefix+id, value)
	if err != nil {
		return err
	}
	f.write(c, prefix+id, encoded, FlowMaxAge)
	return nil
}

// Get returns the value stored for flow id, and false if this browser did not
// start that flow or it has expired.
func (f *FlowCookies) Get(c *gin.Context, prefix, id string) (string, bool) {
	if !flowIDPattern.MatchString(id) {
		return "", false
	}
	raw, err := c.Cookie(prefix + id)
	if err != nil {
		return "", false
	}
	var value string
	if err := f.codec.Decode(prefix+id, raw, &value); err != nil {
		return "", false
	}
	return value, true
}

// Delete ends flow id, so it cannot be completed twice.
func (f *FlowCookies) Delete(c *gin.Context, prefix, id string) {
	if !flowIDPattern.MatchString(id) {
		return
	}
	f.write(c, prefix+id, "", -1)
}

func (f *FlowCookies) write(c *gin.Context, name, value string, maxAge int) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   f.secure,
		SameSite: http.SameSiteLaxMode,
	})
}

type flowError string

func (e flowError) Error() string { return string(e) }

const errInvalidFlowID = flowError("invalid flow id")

// SetAuthorizeRequest, HasAuthorizeRequest and DeleteAuthorizeRequest track a
// pending authorization request for the IdP router.
func (f *FlowCookies) SetAuthorizeRequest(c *gin.Context, arID string) error {
	return f.Set(c, authorizeFlowPrefix, arID, "")
}

func (f *FlowCookies) HasAuthorizeRequest(c *gin.Context, arID string) bool {
	_, ok := f.Get(c, authorizeFlowPrefix, arID)
	return ok
}

func (f *FlowCookies) DeleteAuthorizeRequest(c *gin.Context, arID string) {
	f.Delete(c, authorizeFlowPrefix, arID)
}

// safeRedirect returns rd if it is a path on this site, and "" otherwise. The
// return address travels through the login redirects as a query parameter, so
// anything that could leave the site is dropped rather than followed.
func safeRedirect(rd string) string {
	if !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, `/\`) {
		return ""
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return ""
	}
	return rd
}

// withRedirect appends rd to target as the return address, if there is one.
func withRedirect(target, rd string) string {
	if rd == "" {
		return target
	}
	return target + "?rd=" + url.QueryEscape(rd)
}
