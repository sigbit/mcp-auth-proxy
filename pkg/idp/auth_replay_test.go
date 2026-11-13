package idp

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// Regression test for #167: some clients submit the authorization
// confirmation form a second time shortly after it completed. The
// duplicate submission (and a late GET of the same URL) must replay the
// original redirect within the replay window instead of failing with
// "invalid authorization session". A different session still gets 403.
func TestAuthorizationReturnDuplicateSubmissionReplaysRedirect(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	verifier := oauth2.GenerateVerifier()
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state&code_challenge=%s&code_challenge_method=S256",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"), challenge)

	jar, err := cookiejar.New(nil)
	require.NoError(t, err)
	client := &http.Client{
		Jar: jar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Start the flow: redirect to the authorization return endpoint.
	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authResp.StatusCode)
	returnPath := authResp.Header.Get("Location")
	require.NotEmpty(t, returnPath)

	// GET renders the confirmation form.
	formResp, err := client.Get(server.URL + returnPath)
	require.NoError(t, err)
	defer formResp.Body.Close()
	require.Equal(t, http.StatusOK, formResp.StatusCode)

	// POST completes the authorization and redirects with a code.
	postResp, err := client.Post(server.URL+returnPath, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	defer postResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, postResp.StatusCode)
	callback := postResp.Header.Get("Location")
	require.NotEmpty(t, callback)
	require.Contains(t, callback, "code=")

	// A duplicate POST from the same session replays the same redirect.
	dupResp, err := client.Post(server.URL+returnPath, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	defer dupResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, dupResp.StatusCode,
		"duplicate submission should redirect, not fail")
	require.Equal(t, callback, dupResp.Header.Get("Location"))

	// A late GET of the return URL from the same session also replays it.
	getResp, err := client.Get(server.URL + returnPath)
	require.NoError(t, err)
	defer getResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, getResp.StatusCode)
	require.Equal(t, callback, getResp.Header.Get("Location"))

	// A different session still cannot replay the authorization.
	otherJar, err := cookiejar.New(nil)
	require.NoError(t, err)
	otherClient := &http.Client{
		Jar: otherJar,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	otherResp, err := otherClient.Post(server.URL+returnPath, "application/x-www-form-urlencoded", nil)
	require.NoError(t, err)
	defer otherResp.Body.Close()
	require.Equal(t, http.StatusForbidden, otherResp.StatusCode)
}
