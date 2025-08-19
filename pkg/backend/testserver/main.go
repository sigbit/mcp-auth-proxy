package main

import (
	"log"

	"github.com/mark3labs/mcp-go/server"
)

func main() {
	s := server.NewMCPServer("test", "1.0")
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
