package idp

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/oauth2"
)

// Tests for the dynamic client registration hardening in #191:
// PKCE enforcement for all clients, redirect URI validation at
// registration, and the consent page content.

func TestValidateRedirectURI(t *testing.T) {
	valid := []string{
		"https://claude.ai/api/mcp/auth_callback",
		"https://example.com/cb",
		"http://localhost:8080/callback",
		"http://127.0.0.1:9999/cb",
		"http://[::1]:8080/cb",
	}
	for _, u := range valid {
		require.NoError(t, validateRedirectURI(u), u)
	}

	invalid := []string{
		"http://example.com/cb",       // plain http off loopback
		"http://192.168.1.10/cb",      // non-loopback IP over http
		"https://example.com/cb#frag", // fragment
		"javascript:alert(1)",         // non-http scheme
		"/relative/path",              // not absolute
		"https://",                    // no host
		"not a url",                   // unparseable as absolute URL
	}
	for _, u := range invalid {
		require.Error(t, validateRedirectURI(u), u)
	}
}

func TestRegistrationRejectsInsecureRedirectURI(t *testing.T) {
	server, _, _ := setupTestServer(t)

	register := func(redirectURI string) (int, map[string]any) {
		regReq := registrationRequest{
			ClientName:              "Test Client",
			GrantTypes:              []string{"authorization_code"},
			ResponseTypes:           []string{"code"},
			TokenEndpointAuthMethod: "client_secret_basic",
			Scope:                   "test",
			RedirectURIs:            []string{redirectURI},
		}
		reqBody, err := json.Marshal(regReq)
		require.NoError(t, err)
		resp, err := http.Post(server.URL+RegistrationEndpoint, "application/json", bytes.NewReader(reqBody))
		require.NoError(t, err)
		defer resp.Body.Close()
		var body map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&body)
		return resp.StatusCode, body
	}

	status, body := register("http://app.example.com/cb")
	require.Equal(t, http.StatusBadRequest, status)
	require.Equal(t, "invalid_redirect_uri", body["error"])

	status, _ = register("https://app.example.com/cb")
	require.Equal(t, http.StatusCreated, status)

	status, _ = register("http://localhost:1234/cb")
	require.Equal(t, http.StatusCreated, status)
}

func TestConfidentialClientRequiresPKCE(t *testing.T) {
	server, _, _ := setupTestServer(t)
	regResp := registerTestClient(t, server.URL)

	// No code_challenge: even a confidential client must use PKCE now,
	// so the flow must not deliver an authorization code.
	authURL := fmt.Sprintf("%s%s?response_type=code&client_id=%s&redirect_uri=%s&state=test-state",
		server.URL, AuthorizationEndpoint, regResp.ClientID,
		url.QueryEscape("http://localhost:8080/callback"))

	client := &http.Client{
		Jar: mustCookieJar(t),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authResp.StatusCode)
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)

	if strings.Contains(location, strings.ReplaceAll(AuthorizationReturnEndpoint, ":ar_id", "")) {
		formResp, err := client.Get(server.URL + location)
		require.NoError(t, err)
		defer formResp.Body.Close()
		require.Equal(t, http.StatusOK, formResp.StatusCode)

		authReturnResp, err := client.Post(server.URL+location, "application/x-www-form-urlencoded", nil)
		require.NoError(t, err)
		defer authReturnResp.Body.Close()
		require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authReturnResp.StatusCode)
		location = authReturnResp.Header.Get("Location")
	}

	callbackURL, err := url.Parse(location)
	require.NoError(t, err)
	require.Empty(t, callbackURL.Query().Get("code"), "code must not be issued without PKCE")
	require.NotEmpty(t, callbackURL.Query().Get("error"))
}

func TestConsentFormShowsClientAndRedirectURI(t *testing.T) {
	server, _, _ := setupTestServerBackend(t, "kvs", `<b>Access</b>`, `<script>danger</script>`)
	regResp := registerTestClient(t, server.URL)

	config := &oauth2.Config{
		ClientID:    regResp.ClientID,
		RedirectURL: "http://localhost:8080/callback",
		Scopes:      []string{"test"},
		Endpoint: oauth2.Endpoint{
			AuthURL:  server.URL + AuthorizationEndpoint,
			TokenURL: server.URL + TokenEndpoint,
		},
	}
	verifier := oauth2.GenerateVerifier()
	authURL := config.AuthCodeURL("test-state", oauth2.S256ChallengeOption(verifier))

	client := &http.Client{
		Jar: mustCookieJar(t),
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	authResp, err := client.Get(authURL)
	require.NoError(t, err)
	defer authResp.Body.Close()
	require.Contains(t, []int{http.StatusFound, http.StatusSeeOther}, authResp.StatusCode)
	location := authResp.Header.Get("Location")
	require.NotEmpty(t, location)

	formResp, err := client.Get(server.URL + location)
	require.NoError(t, err)
	defer formResp.Body.Close()
	require.Equal(t, http.StatusOK, formResp.StatusCode)

	body, err := io.ReadAll(formResp.Body)
	require.NoError(t, err)
	require.Contains(t, string(body), "<h1>&lt;b&gt;Access&lt;/b&gt;</h1>")
	require.Contains(t, string(body), "&lt;script&gt;danger&lt;/script&gt;")
	require.NotContains(t, string(body), "<script>")
	require.Contains(t, string(body), "Requested scopes: test")
	require.Contains(t, string(body), regResp.ClientID, "consent form must identify the client")
	require.Contains(t, string(body), "http://localhost:8080/callback", "consent form must show where the result will be sent")
}
