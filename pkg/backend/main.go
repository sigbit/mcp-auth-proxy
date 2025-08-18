package backend

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/client"
	"github.com/mark3labs/mcp-go/client/transport"
	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"go.uber.org/zap"
)

var MCPClientInitTimeout = 1 * time.Minute

type ProxyBackend struct {
	logger *zap.Logger
	cmd    []string
	errCh  chan error
	client *client.Client
}

func NewProxyBackend(logger *zap.Logger, cmd []string) *ProxyBackend {
	return &ProxyBackend{
		logger: logger,
		cmd:    cmd,
		errCh:  nil,
	}
}

func (p *ProxyBackend) Run(ctx context.Context) (http.Handler, error) {
	if p.errCh != nil {
		return nil, fmt.Errorf("proxy backend is already running")
	}
	execCmd := exec.CommandContext(ctx, p.cmd[0], p.cmd[1:]...)
	stdout, err := execCmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdout pipe: %w", err)
	}
	stdin, err := execCmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to get stdin pipe: %w", err)
	}
	execCmd.Stderr = os.Stderr
	if err := execCmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start exec command: %w", err)
	}
	p.errCh = make(chan error)
	done := make(chan struct{})
	go func() {
		if err := execCmd.Wait(); err != nil {
			p.errCh <- fmt.Errorf("exec command failed: %s: %w", strings.Join(p.cmd, " "), err)
		}
	}()
	var handler http.Handler
	go func() {
		tr := transport.NewIO(stdout, stdin, os.Stderr)
		transport.WithCommandLogger(&zapLogger{p.logger})(tr)
		_client, _handler, err := setupProxy(ctx, p.logger, tr)
		if err != nil {
			p.errCh <- err
			return
		}
		p.client = _client
		handler = _handler
		done <- struct{}{}
	}()
	select {
	case err := <-p.errCh:
		return nil, err
	case <-done:
		return handler, nil
	}
}

func (p *ProxyBackend) Wait() error {
	if p.errCh == nil {
		return nil
	}
	return <-p.errCh
}

func (p *ProxyBackend) Close() error {
	if p.client != nil {
		return p.client.Close()
	}
	return nil
}

func setupProxy(ctx context.Context, logger *zap.Logger, tr *transport.Stdio) (*client.Client, http.Handler, error) {
	c := client.NewClient(tr)
	if err := c.Start(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to start MCP client: %w", err)
	}
	init, err := c.Initialize(ctx, mcp.InitializeRequest{})
	if err != nil {
		c.Close()
		return nil, nil, fmt.Errorf("failed to initialize MCP client: %w", err)
	}
	s := server.NewMCPServer(init.ServerInfo.Name, init.ServerInfo.Version)
	if init.Capabilities.Tools != nil {
		tools, err := c.ListTools(ctx, mcp.ListToolsRequest{})
		if err != nil {
			c.Close()
			return nil, nil, fmt.Errorf("failed to list tools: %w", err)
		}
		for _, tool := range tools.Tools {
			s.AddTool(tool, c.CallTool)
		}
	}
	if init.Capabilities.Prompts != nil {
		prompts, err := c.ListPrompts(ctx, mcp.ListPromptsRequest{})
		if err != nil {
			c.Close()
			return nil, nil, fmt.Errorf("failed to list prompts: %w", err)
		}
		for _, prompt := range prompts.Prompts {
			s.AddPrompt(prompt, c.GetPrompt)
		}
	}
	if init.Capabilities.Resources != nil {
		resources, err := c.ListResources(ctx, mcp.ListResourcesRequest{})
		if err != nil {
			c.Close()
			return nil, nil, fmt.Errorf("failed to list resources: %w", err)
		}
		for _, resource := range resources.Resources {
			s.AddResource(resource, func(ctx context.Context, request mcp.ReadResourceRequest) ([]mcp.ResourceContents, error) {
				res, err := c.ReadResource(ctx, request)
				if err != nil {
					return nil, err
				}
				return res.Contents, nil
			})
		}
	}
	ss := server.NewStreamableHTTPServer(
		s,
		server.WithEndpointPath("/mcp"),
		server.WithStateLess(true),
		server.WithLogger(&zapLogger{logger}),
	)
	return c, ss, nil
}

type zapLogger struct {
	logger *zap.Logger
}

func (l *zapLogger) Infof(format string, v ...any) {
	l.logger.Info(fmt.Sprintf(format, v...))
}

func (l *zapLogger) Errorf(format string, v ...any) {
	l.logger.Error(fmt.Sprintf(format, v...))
}
