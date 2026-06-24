package main

import (
	"context"
	"encoding/json"
	"log"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

var rawDraft07Schema = json.RawMessage(`{
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

func main() {
	s := server.NewMCPServer("test", "1.0")
	s.AddTool(
		mcp.NewToolWithRawSchema("with_defs", "stdio fixture", rawDraft07Schema),
		func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			return mcp.NewToolResultText(""), nil
		},
	)
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
