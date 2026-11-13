package backend

import (
	"context"
	"encoding/json"
	"fmt"
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

// failFirstToolsList wraps a BidirectionalInterface and fails the first
// tools/list request, delegating all other calls. The raw helper issues the
// first tools/list; the typed fallback issues the second.
type failFirstToolsList struct {
	transport.BidirectionalInterface
	toolsListCount int
}

func (f *failFirstToolsList) SendRequest(ctx context.Context, req transport.JSONRPCRequest) (*transport.JSONRPCResponse, error) {
	if req.Method == "tools/list" {
		f.toolsListCount++
		if f.toolsListCount == 1 {
			return nil, fmt.Errorf("simulated raw tools/list failure")
		}
	}
	return f.BidirectionalInterface.SendRequest(ctx, req)
}

func TestSetupProxyFallsBackOnRawListError(t *testing.T) {
	logger := zap.NewNop()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	s := server.NewMCPServer("test", "1.0")
	s.AddTool(
		mcp.NewTool("ping", mcp.WithDescription("ping tool")),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText("pong"), nil
		},
	)
	httpServer := server.NewStreamableHTTPServer(
		s,
		server.WithEndpointPath("/mcp"),
		server.WithStateLess(true),
	)

	testServer := httptest.NewServer(httpServer)
	defer testServer.Close()

	tr, err := transport.NewStreamableHTTP(testServer.URL + "/mcp")
	require.NoError(t, err, "failed to create HTTP transport")

	c, handler, err := setupProxy(ctx, logger, &failFirstToolsList{BidirectionalInterface: tr})
	require.NoError(t, err, "setupProxy should succeed via typed fallback")
	require.NotNil(t, handler, "handler should not be nil")
	require.NotNil(t, c, "client should not be nil")
	defer c.Close()

	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()
	schemas := rawProxyToolSchemas(t, proxyServer.URL)
	require.Contains(t, schemas, "ping", "typed fallback should still relay the upstream tool")
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
		pb.Wait()
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

func TestProxyBackendRunPreservesSchema(t *testing.T) {
	logger := zap.NewNop()
	pb := NewProxyBackend(logger, []string{"go", "run", "./testserver"})
	defer pb.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	handler, err := pb.Run(ctx)
	require.NoError(t, err, "Run should not return error")
	require.NotNil(t, handler, "handler should not be nil")

	proxyServer := httptest.NewServer(handler)
	defer proxyServer.Close()

	tr, err := transport.NewStreamableHTTP(proxyServer.URL + "/mcp")
	require.NoError(t, err, "failed to create proxy transport")

	c := client.NewClient(tr)
	require.NoError(t, c.Start(ctx), "client should start")
	defer c.Close()
	_, err = c.Initialize(ctx, mcp.InitializeRequest{})
	require.NoError(t, err, "client should initialize")

	resp, err := tr.SendRequest(ctx, transport.JSONRPCRequest{
		JSONRPC: mcp.JSONRPC_VERSION,
		ID:      mcp.NewRequestId("test/tools-list"),
		Method:  "tools/list",
	})
	require.NoError(t, err, "raw tools/list should succeed")
	require.Nil(t, resp.Error, "raw tools/list should not return an error")

	var m map[string]any
	require.NoError(t, json.Unmarshal(resp.Result, &m), "decode tools/list result")

	toolsAny, ok := m["tools"].([]any)
	require.True(t, ok, "tools/list result should contain a tools array")

	var withDefs map[string]any
	for _, ta := range toolsAny {
		tool, ok := ta.(map[string]any)
		require.True(t, ok, "each tool should be an object")
		if name, _ := tool["name"].(string); name == "with_defs" {
			withDefs = tool
		}
	}
	require.NotNil(t, withDefs, "with_defs tool should be relayed")

	input, ok := withDefs["inputSchema"].(map[string]any)
	require.True(t, ok, "with_defs should have an inputSchema object")
	require.Contains(t, input, "definitions", "definitions block must be preserved over stdio")
	require.NotContains(t, input, "$defs", "definitions must not be rewritten to $defs over stdio")

	properties, ok := input["properties"].(map[string]any)
	require.True(t, ok, "inputSchema should have properties")
	item, ok := properties["item"].(map[string]any)
	require.True(t, ok, "properties.item should be an object")
	require.Equal(t, "#/definitions/Item", item["$ref"], "$ref must still target #/definitions/Item over stdio")
}
