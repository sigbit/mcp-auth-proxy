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

// Fixture schemas used by the integration tests. They are registered on the
// upstream via mcp.NewToolWithRawSchema so the upstream serves these exact bytes
// (registering a typed schema would let the upstream normalize definitions->$defs
// before the proxy ever sees it, masking the bug under test).
var (
	// (a) draft-07 schema with a "definitions" block and a #/definitions/Item $ref.
	fixtureDefinitionsRef = json.RawMessage(`{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"definitions": {
			"Item": {"type": "string"}
		},
		"properties": {
			"item": {"$ref": "#/definitions/Item"}
		},
		"required": ["item"]
	}`)

	// (b) schema carrying root-level $schema, title, and oneOf.
	fixtureUnmodeledKeywords = json.RawMessage(`{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"title": "ChoiceInput",
		"type": "object",
		"properties": {
			"value": {"type": "string"}
		},
		"oneOf": [
			{"required": ["value"]},
			{"required": []}
		]
	}`)

	// (c) native $defs schema referencing #/$defs/...
	fixtureNativeDefs = json.RawMessage(`{
		"$schema": "https://json-schema.org/draft/2020-12/schema",
		"type": "object",
		"$defs": {
			"Item": {"type": "string"}
		},
		"properties": {
			"item": {"$ref": "#/$defs/Item"}
		}
	}`)

	// (d) plain object schema with no $ref/$defs.
	fixturePlain = json.RawMessage(`{
		"type": "object",
		"properties": {
			"name": {"type": "string"},
			"count": {"type": "integer"}
		},
		"required": ["name"]
	}`)

	// (e) draft-07 output schema with definitions/$ref.
	fixtureOutputDefinitionsRef = json.RawMessage(`{
		"$schema": "http://json-schema.org/draft-07/schema#",
		"type": "object",
		"definitions": {
			"Result": {"type": "number"}
		},
		"properties": {
			"result": {"$ref": "#/definitions/Result"}
		}
	}`)
)

// newProxyTestHarness builds an in-process upstream MCP server serving the given
// tools, runs setupProxy against it, exposes the proxy handler over HTTP, and
// returns the proxy server's URL. All servers/clients are torn down via t.Cleanup.
func newProxyTestHarness(t *testing.T, tools ...mcp.Tool) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	upstream := server.NewMCPServer("upstream", "1.0")
	for _, tool := range tools {
		upstream.AddTool(tool, func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText(""), nil
		})
	}
	upstreamServer := httptest.NewServer(server.NewStreamableHTTPServer(
		upstream,
		server.WithEndpointPath("/mcp"),
		server.WithStateLess(true),
	))
	t.Cleanup(upstreamServer.Close)

	tr, err := transport.NewStreamableHTTP(upstreamServer.URL + "/mcp")
	require.NoError(t, err, "failed to create upstream transport")

	c, handler, err := setupProxy(ctx, zap.NewNop(), tr)
	require.NoError(t, err, "setupProxy should not return error")
	t.Cleanup(func() { _ = c.Close() })

	proxyServer := httptest.NewServer(handler)
	t.Cleanup(proxyServer.Close)

	return proxyServer.URL
}

// rawProxyToolSchemas connects to the proxy and reads the raw tools/list wire
// bytes (NOT via client.ListTools, which would re-normalize schemas through the
// lossy ToolArgumentsSchema and mask the proxy's correct output). It returns a
// map of tool name -> the raw inputSchema/outputSchema objects, keyed "inputSchema"
// and "outputSchema".
func rawProxyToolSchemas(t *testing.T, proxyURL string) map[string]map[string]any {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	t.Cleanup(cancel)

	tr, err := transport.NewStreamableHTTP(proxyURL + "/mcp")
	require.NoError(t, err, "failed to create proxy transport")

	c := client.NewClient(tr)
	require.NoError(t, c.Start(ctx), "client should start")
	t.Cleanup(func() { _ = c.Close() })
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

	out := make(map[string]map[string]any)
	for _, ta := range toolsAny {
		tool, ok := ta.(map[string]any)
		require.True(t, ok, "each tool should be an object")
		name, _ := tool["name"].(string)
		schemas := make(map[string]any)
		if input, ok := tool["inputSchema"].(map[string]any); ok {
			schemas["inputSchema"] = input
		}
		if output, ok := tool["outputSchema"].(map[string]any); ok {
			schemas["outputSchema"] = output
		}
		out[name] = schemas
	}
	return out
}

func TestRelayPreservesDefinitionsAndRef(t *testing.T) {
	tool := mcp.NewToolWithRawSchema("with_defs", "definitions fixture", fixtureDefinitionsRef)
	proxyURL := newProxyTestHarness(t, tool)

	schemas := rawProxyToolSchemas(t, proxyURL)
	require.Contains(t, schemas, "with_defs")
	input, ok := schemas["with_defs"]["inputSchema"].(map[string]any)
	require.True(t, ok, "with_defs should have an inputSchema object")

	require.Contains(t, input, "definitions", "definitions block must be preserved")
	require.NotContains(t, input, "$defs", "definitions must not be rewritten to $defs")

	properties, ok := input["properties"].(map[string]any)
	require.True(t, ok, "inputSchema should have properties")
	item, ok := properties["item"].(map[string]any)
	require.True(t, ok, "properties.item should be an object")
	require.Equal(t, "#/definitions/Item", item["$ref"], "$ref must still target #/definitions/Item")
}

func TestRelayPreservesUnmodeledKeywords(t *testing.T) {
	tool := mcp.NewToolWithRawSchema("with_keywords", "unmodeled keywords fixture", fixtureUnmodeledKeywords)
	proxyURL := newProxyTestHarness(t, tool)

	schemas := rawProxyToolSchemas(t, proxyURL)
	require.Contains(t, schemas, "with_keywords")
	input, ok := schemas["with_keywords"]["inputSchema"].(map[string]any)
	require.True(t, ok, "with_keywords should have an inputSchema object")

	require.Contains(t, input, "$schema", "root-level $schema must be preserved")
	require.Equal(t, "ChoiceInput", input["title"], "root-level title must be preserved")
	require.Contains(t, input, "oneOf", "root-level oneOf must be preserved")
}

func TestRelayPreservesNativeDefs(t *testing.T) {
	tool := mcp.NewToolWithRawSchema("with_native_defs", "native defs fixture", fixtureNativeDefs)
	proxyURL := newProxyTestHarness(t, tool)

	schemas := rawProxyToolSchemas(t, proxyURL)
	require.Contains(t, schemas, "with_native_defs")
	input, ok := schemas["with_native_defs"]["inputSchema"].(map[string]any)
	require.True(t, ok, "with_native_defs should have an inputSchema object")

	require.Contains(t, input, "$defs", "$defs block must be preserved")
	require.NotContains(t, input, "definitions", "native $defs must not become definitions")

	properties, ok := input["properties"].(map[string]any)
	require.True(t, ok, "inputSchema should have properties")
	item, ok := properties["item"].(map[string]any)
	require.True(t, ok, "properties.item should be an object")
	require.Equal(t, "#/$defs/Item", item["$ref"], "$ref must still target #/$defs/Item")
}

func TestRelayPlainSchemaUnchanged(t *testing.T) {
	tool := mcp.NewToolWithRawSchema("with_plain", "plain schema fixture", fixturePlain)
	proxyURL := newProxyTestHarness(t, tool)

	schemas := rawProxyToolSchemas(t, proxyURL)
	require.Contains(t, schemas, "with_plain")
	input, ok := schemas["with_plain"]["inputSchema"].(map[string]any)
	require.True(t, ok, "with_plain should have an inputSchema object")

	require.Equal(t, "object", input["type"], "type must survive intact")

	properties, ok := input["properties"].(map[string]any)
	require.True(t, ok, "properties must survive intact")
	require.Contains(t, properties, "name")
	require.Contains(t, properties, "count")

	required, ok := input["required"].([]any)
	require.True(t, ok, "required must survive intact")
	require.Equal(t, []any{"name"}, required)
}

func TestRelayPreservesOutputSchema(t *testing.T) {
	tool := mcp.NewToolWithRawSchema("with_output", "output schema fixture", fixturePlain)
	tool.RawOutputSchema = fixtureOutputDefinitionsRef
	proxyURL := newProxyTestHarness(t, tool)

	schemas := rawProxyToolSchemas(t, proxyURL)
	require.Contains(t, schemas, "with_output")
	output, ok := schemas["with_output"]["outputSchema"].(map[string]any)
	require.True(t, ok, "with_output should have an outputSchema object")

	require.Contains(t, output, "definitions", "output definitions block must be preserved")
	require.NotContains(t, output, "$defs", "output definitions must not be rewritten to $defs")

	properties, ok := output["properties"].(map[string]any)
	require.True(t, ok, "outputSchema should have properties")
	result, ok := properties["result"].(map[string]any)
	require.True(t, ok, "properties.result should be an object")
	require.Equal(t, "#/definitions/Result", result["$ref"], "$ref must still target #/definitions/Result")
}

func TestRelayMultipleTools(t *testing.T) {
	defsTool := mcp.NewToolWithRawSchema("with_defs", "definitions fixture", fixtureDefinitionsRef)
	nativeTool := mcp.NewToolWithRawSchema("with_native_defs", "native defs fixture", fixtureNativeDefs)
	proxyURL := newProxyTestHarness(t, defsTool, nativeTool)

	schemas := rawProxyToolSchemas(t, proxyURL)
	require.Contains(t, schemas, "with_defs")
	require.Contains(t, schemas, "with_native_defs")

	defsInput, ok := schemas["with_defs"]["inputSchema"].(map[string]any)
	require.True(t, ok, "with_defs should have an inputSchema object")
	require.Contains(t, defsInput, "definitions", "with_defs must keep its definitions block")
	require.NotContains(t, defsInput, "$defs", "with_defs must not pick up $defs from the other tool")

	nativeInput, ok := schemas["with_native_defs"]["inputSchema"].(map[string]any)
	require.True(t, ok, "with_native_defs should have an inputSchema object")
	require.Contains(t, nativeInput, "$defs", "with_native_defs must keep its $defs block")
	require.NotContains(t, nativeInput, "definitions", "with_native_defs must not pick up definitions from the other tool")
}

// fakeTransport implements transport.Interface, returning canned tools/list
// responses keyed by the request's pagination cursor.
type fakeTransport struct {
	responses map[mcp.Cursor]json.RawMessage
}

func (f *fakeTransport) Start(ctx context.Context) error { return nil }

func (f *fakeTransport) SendRequest(ctx context.Context, req transport.JSONRPCRequest) (*transport.JSONRPCResponse, error) {
	var cursor mcp.Cursor
	if p, ok := req.Params.(mcp.PaginatedParams); ok {
		cursor = p.Cursor
	}
	result, ok := f.responses[cursor]
	if !ok {
		return nil, fmt.Errorf("fakeTransport: no canned response for cursor %q", cursor)
	}
	return &transport.JSONRPCResponse{Result: result}, nil
}

func (f *fakeTransport) SendNotification(ctx context.Context, n mcp.JSONRPCNotification) error {
	return nil
}

func (f *fakeTransport) SetNotificationHandler(handler func(notification mcp.JSONRPCNotification)) {
}

func (f *fakeTransport) Close() error { return nil }

func (f *fakeTransport) GetSessionId() string { return "" }

func TestListToolsPreservingSchema_Pagination(t *testing.T) {
	inputA := json.RawMessage(`{"type":"object","definitions":{"Item":{"type":"string"}},"properties":{"a":{"$ref":"#/definitions/Item"}}}`)
	inputB := json.RawMessage(`{"type":"object","properties":{"b":{"type":"number"}}}`)

	page0 := json.RawMessage(`{"tools":[{"name":"alpha","description":"first","inputSchema":` + string(inputA) + `}],"nextCursor":"p1"}`)
	page1 := json.RawMessage(`{"tools":[{"name":"beta","description":"second","inputSchema":` + string(inputB) + `}]}`)

	tr := &fakeTransport{responses: map[mcp.Cursor]json.RawMessage{
		"":   page0,
		"p1": page1,
	}}

	tools, err := listToolsPreservingSchema(context.Background(), tr)
	require.NoError(t, err)
	require.Len(t, tools, 2)
	require.Equal(t, "alpha", tools[0].Name)
	require.Equal(t, "beta", tools[1].Name)
	require.JSONEq(t, string(inputA), string(tools[0].RawInputSchema))
	require.JSONEq(t, string(inputB), string(tools[1].RawInputSchema))
}

func TestListToolsPreservingSchema_OmittedSchema(t *testing.T) {
	page0 := json.RawMessage(`{"tools":[{"name":"noschema","description":"no input schema"}]}`)

	tr := &fakeTransport{responses: map[mcp.Cursor]json.RawMessage{
		"": page0,
	}}

	tools, err := listToolsPreservingSchema(context.Background(), tr)
	require.NoError(t, err)
	require.Len(t, tools, 1)
	require.Equal(t, "noschema", tools[0].Name)
	require.Nil(t, tools[0].RawInputSchema)
}
