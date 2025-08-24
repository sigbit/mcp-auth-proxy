package backend

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestSetupProxy(t *testing.T) {
	logger := zap.NewNop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	// Create a test MCP server
	s := server.NewMCPServer("test", "1.0")
	httpServer := server.NewStreamableHTTPServer(
		s,
		server.WithEndpointPath("/mcp"),
		server.WithStateLess(true),
	)

	// Start HTTP test server
	testServer := httptest.NewServer(httpServer)
	defer testServer.Close()

	// Create HTTP transport client
	serverAddr := testServer.URL
	mcpEndpoint := serverAddr + "/mcp"

	tr, err := transport.NewStreamableHTTP(mcpEndpoint)
	require.NoError(t, err, "failed to create HTTP transport")

	// Test the setupProxy function with HTTP transport
	c, handler, err := setupProxy(ctx, logger, tr)
	require.NoError(t, err, "setupProxy should not return error")
	require.NotNil(t, c, "client should not be nil")
	require.NotNil(t, handler, "handler should not be nil")

	// Verify the client can actually connect
	clientConn := client.NewClient(tr)
	defer clientConn.Close()

	err = clientConn.Start(ctx)
	require.NoError(t, err, "client should start successfully")

	init, err := clientConn.Initialize(ctx, mcp.InitializeRequest{})
	require.NoError(t, err, "client should initialize successfully")
	require.Equal(t, "test", init.ServerInfo.Name)
	require.Equal(t, "1.0", init.ServerInfo.Version)
}

func TestProxyBackendRunWithInvalidCommand(t *testing.T) {
	logger := zap.NewNop()
	pb := NewProxyBackend(logger, []string{"sh", "-c", "exit 0"})
	defer pb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	handler, err := pb.Run(ctx)
	require.Error(t, err, "expected error for invalid command")
	require.Nil(t, handler, "handler should be nil on error")
}

func TestProxyBackendRun(t *testing.T) {
	logger := zap.NewNop()
	cmd := []string{"go", "run", "./testserver"}
	pb := NewProxyBackend(logger, cmd)
	defer pb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)

	handler, err := pb.Run(ctx)
	require.NoError(t, err, "Run should not return error")
	require.NotNil(t, handler, "handler should not be nil")

	checkCh := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(checkCh)
	}()

	timeout := time.After(10 * time.Millisecond)
	select {
	case <-checkCh:
		t.Error("Test completed too early")
	case <-timeout:
		// Test timed out
	}

	cancel()

	timeout = time.After(10 * time.Second)
	select {
	case <-checkCh:
		// Test completed successfully
	case <-timeout:
		t.Error("Test timed out")
	}
}
