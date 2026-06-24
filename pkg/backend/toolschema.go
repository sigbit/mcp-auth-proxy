package backend

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
)

// rawToolsListResult captures each tool's schema exactly as the upstream
// emitted it, before mcp-go's lossy ToolArgumentsSchema (de)serialization can
// rewrite "definitions" -> "$defs" or drop unmodeled keywords.
type rawToolsListResult struct {
	Tools []struct {
		InputSchema  json.RawMessage `json:"inputSchema"`
		OutputSchema json.RawMessage `json:"outputSchema"`
	} `json:"tools"`
}

// listToolsPreservingSchema performs a paginated tools/list directly over the
// transport so the original inputSchema/outputSchema bytes survive verbatim.
// Tool metadata (name, description, annotations, _meta, ...) still comes from
// mcp-go's typed parse; only the schemas are carried as Raw*Schema so the proxy
// server re-emits them unchanged.
func listToolsPreservingSchema(ctx context.Context, tr transport.Interface) ([]mcp.Tool, error) {
	var out []mcp.Tool
	var cursor mcp.Cursor
	for page := 0; ; page++ {
		req := mcp.ListToolsRequest{}
		if cursor != "" {
			req.Params.Cursor = cursor
		}
		resp, err := tr.SendRequest(ctx, transport.JSONRPCRequest{
			JSONRPC: mcp.JSONRPC_VERSION,
			ID:      mcp.NewRequestId(fmt.Sprintf("mcp-auth-proxy/tools-list/%d", page)),
			Method:  "tools/list",
			Params:  req.Params,
		})
		if err != nil {
			return nil, fmt.Errorf("tools/list request failed: %w", err)
		}
		if resp.Error != nil {
			return nil, fmt.Errorf("tools/list error: %w", resp.Error.AsError())
		}

		var typed mcp.ListToolsResult
		if err := json.Unmarshal(resp.Result, &typed); err != nil {
			return nil, fmt.Errorf("decode tools/list: %w", err)
		}
		var raw rawToolsListResult
		if err := json.Unmarshal(resp.Result, &raw); err != nil {
			return nil, fmt.Errorf("decode tools/list (raw schemas): %w", err)
		}

		for i := range typed.Tools {
			t := typed.Tools[i]
			if i < len(raw.Tools) {
				if s := raw.Tools[i].InputSchema; len(s) > 0 {
					t.RawInputSchema = s
					t.InputSchema = mcp.ToolInputSchema{}
				}
				if s := raw.Tools[i].OutputSchema; len(s) > 0 {
					t.RawOutputSchema = s
					t.OutputSchema = mcp.ToolOutputSchema{}
				}
			}
			out = append(out, t)
		}

		cursor = typed.NextCursor
		if cursor == "" {
			return out, nil
		}
	}
}
