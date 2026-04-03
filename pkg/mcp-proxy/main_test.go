package mcpproxy

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"testing"

	"github.com/sigbit/mcp-auth-proxy/pkg/proxy"
	"github.com/stretchr/testify/require"
)

func TestRun_NormalizesExternalURLTrailingSlash(t *testing.T) {
	originalNewProxyRouter := newProxyRouter
	t.Cleanup(func() {
		newProxyRouter = originalNewProxyRouter
	})

	cases := []struct {
		name        string
		input       string
		wantURL     string
		wantErr     bool
		errContains string
	}{
		{name: "no trailing slash", input: "https://example.com", wantURL: "https://example.com/"},
		{name: "with trailing slash", input: "https://example.com/", wantURL: "https://example.com/"},
		{name: "with path", input: "https://example.com/foo", wantErr: true, errContains: "must not have a path"},
	}

	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			var receivedURL string
			newProxyRouter = func(externalURL string, proxyHandler http.Handler, publicKey *rsa.PublicKey, proxyHeaders http.Header, httpStreamingOnly bool, passUserHeaders bool) (*proxy.ProxyRouter, error) {
				receivedURL = externalURL
				return nil, errors.New("stop early")
			}

			err := Run(
				":0", ":0", false, "", "", false, "", "",
				t.TempDir(), "local", "",
				tt.input,
				"", "", nil, nil,
				"", "", nil, nil,
				"", "", "", nil, "", "", nil, nil, nil, nil,
				false, "", "", nil, nil, "",
				[]string{"http://example.com"}, false,
				false,
			)

			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContains)
				return
			}

			require.Error(t, err)
			require.Contains(t, err.Error(), "stop early")
			require.Equal(t, tt.wantURL, receivedURL)
		})
	}
}

func TestRun_PassesHTTPStreamingOnlyToProxyRouter(t *testing.T) {
	originalNewProxyRouter := newProxyRouter
	t.Cleanup(func() {
		newProxyRouter = originalNewProxyRouter
	})

	var streamingOnlyReceived bool
	newProxyRouter = func(externalURL string, proxyHandler http.Handler, publicKey *rsa.PublicKey, proxyHeaders http.Header, httpStreamingOnly bool, passUserHeaders bool) (*proxy.ProxyRouter, error) {
		streamingOnlyReceived = httpStreamingOnly
		return nil, errors.New("proxy router init failed")
	}

	err := Run(
		":0",
		":0",
		false,
		"",
		"",
		false,
		"",
		"",
		t.TempDir(),
		"local",
		"",
		"http://localhost",
		"",
		"",
		nil,
		nil,
		"",
		"",
		nil,
		nil,
		"",
		"",
		"",
		nil,
		"",
		"",
		nil,
		nil,
		nil,
		nil,
		false,
		"",
		"",
		nil,
		nil,
		"",
		[]string{"http://example.com"},
		true,
		false,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create proxy router")
	require.True(t, streamingOnlyReceived, "httpStreamingOnly should be forwarded to proxy router")
}

func TestRun_PassesPassUserHeadersToProxyRouter(t *testing.T) {
	originalNewProxyRouter := newProxyRouter
	t.Cleanup(func() {
		newProxyRouter = originalNewProxyRouter
	})

	var passUserHeadersReceived bool
	newProxyRouter = func(externalURL string, proxyHandler http.Handler, publicKey *rsa.PublicKey, proxyHeaders http.Header, httpStreamingOnly bool, passUserHeaders bool) (*proxy.ProxyRouter, error) {
		passUserHeadersReceived = passUserHeaders
		return nil, errors.New("proxy router init failed")
	}

	err := Run(
		":0",
		":0",
		false,
		"",
		"",
		false,
		"",
		"",
		t.TempDir(),
		"local",
		"",
		"http://localhost",
		"",
		"",
		nil,
		nil,
		"",
		"",
		nil,
		nil,
		"",
		"",
		"",
		nil,
		"",
		"",
		nil,
		nil,
		nil,
		nil,
		false,
		"",
		"",
		nil,
		nil,
		"",
		[]string{"http://example.com"},
		false,
		true,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create proxy router")
	require.True(t, passUserHeadersReceived, "passUserHeaders should be forwarded to proxy router")
}
