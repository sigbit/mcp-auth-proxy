package mcpproxy

import (
	"crypto/rsa"
	"errors"
	"net/http"
	"testing"

	"github.com/sigbit/mcp-auth-proxy/pkg/proxy"
	"github.com/stretchr/testify/require"
)

func TestRun_PassesHTTPStreamingOnlyToProxyRouter(t *testing.T) {
	originalNewProxyRouter := newProxyRouter
	t.Cleanup(func() {
		newProxyRouter = originalNewProxyRouter
	})

	var streamingOnlyReceived bool
	newProxyRouter = func(externalURL string, proxyHandler http.Handler, publicKey *rsa.PublicKey, proxyHeaders http.Header, httpStreamingOnly bool) (*proxy.ProxyRouter, error) {
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
		false,
		"",
		"",
		nil,
		nil,
		"",
		[]string{"http://example.com"},
		true,
	)

	require.Error(t, err)
	require.Contains(t, err.Error(), "failed to create proxy router")
	require.True(t, streamingOnlyReceived, "httpStreamingOnly should be forwarded to proxy router")
}
