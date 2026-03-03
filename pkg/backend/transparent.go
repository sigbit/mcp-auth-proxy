package backend

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"sync"

	"go.uber.org/zap"
)

type TransparentBackend struct {
	logger  *zap.Logger
	url     *url.URL
	trusted []netip.Prefix
	ctx     context.Context
	ctxLock sync.Mutex
}

func NewTransparentBackend(logger *zap.Logger, u *url.URL, trusted []string) (Backend, error) {
	trn := make([]netip.Prefix, 0, len(trusted))
	for _, c := range trusted {
		p, err := netip.ParsePrefix(c)
		if err != nil {
			return nil, err
		}
		trn = append(trn, p)
	}

	return &TransparentBackend{
		logger:  logger,
		url:     u,
		trusted: trn,
	}, nil
}

const maxBackendRedirects = 10

// redirectFollowingTransport wraps an http.RoundTripper to transparently
// follow 307/308 redirects from backend servers. This is needed because
// httputil.ReverseProxy uses Transport.RoundTrip() directly, which does
// not follow redirects. Many MCP backends (Starlette/FastAPI) redirect
// /mcp → /mcp/ via 307, which POST-based MCP clients won't follow.
type redirectFollowingTransport struct {
	base       http.RoundTripper
	targetHost string // only follow redirects to this host
}

func (t *redirectFollowingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// Buffer body upfront so we can replay it on redirect.
	// MCP JSON-RPC payloads are small, so this is fine.
	var bodyBytes []byte
	if req.Body != nil {
		var err error
		bodyBytes, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(bodyBytes))
	}

	for i := 0; i <= maxBackendRedirects; i++ {
		resp, err := t.base.RoundTrip(req)
		if err != nil {
			return nil, err
		}

		// Only follow 307 (Temporary) and 308 (Permanent) redirects.
		// These preserve the original method and body per HTTP spec.
		if resp.StatusCode != http.StatusTemporaryRedirect &&
			resp.StatusCode != http.StatusPermanentRedirect {
			return resp, nil
		}

		location := resp.Header.Get("Location")
		if location == "" {
			return resp, nil
		}

		// Resolve relative Location against the request URL
		newURL, err := req.URL.Parse(location)
		if err != nil {
			return resp, nil
		}

		// Security: only follow redirects to the same backend host.
		// Don't leak Authorization headers or body to arbitrary hosts.
		if newURL.Host != "" && newURL.Host != t.targetHost {
			return resp, nil
		}

		// Drain and close the redirect response body
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		// Clone the request for the next hop, replaying the body
		newReq := req.Clone(req.Context())
		newReq.URL = newURL
		newReq.Host = newURL.Host
		if bodyBytes != nil {
			newReq.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			newReq.ContentLength = int64(len(bodyBytes))
		}
		req = newReq
	}

	return nil, fmt.Errorf("backend exceeded maximum redirects (%d)", maxBackendRedirects)
}

func (p *TransparentBackend) Run(ctx context.Context) (http.Handler, error) {
	p.ctxLock.Lock()
	defer p.ctxLock.Unlock()
	if p.ctx != nil {
		return nil, fmt.Errorf("transparent backend is already running")
	}
	p.ctx = ctx
	rp := httputil.ReverseProxy{
		Transport: &redirectFollowingTransport{
			base:       http.DefaultTransport,
			targetHost: p.url.Host,
		},
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(p.url)
			if p.isTrusted(pr.In.RemoteAddr) {
				pr.Out.Header["X-Forwarded-For"] = pr.In.Header["X-Forwarded-For"]
			}
			pr.SetXForwarded()
			if p.isTrusted(pr.In.RemoteAddr) {
				if v := pr.In.Header.Get("X-Forwarded-Host"); v != "" {
					pr.Out.Header.Set("X-Forwarded-Host", v)
				}
				if v := pr.In.Header.Get("X-Forwarded-Proto"); v != "" {
					pr.Out.Header.Set("X-Forwarded-Proto", v)
				}
				if v := pr.In.Header.Get("X-Forwarded-Port"); v != "" {
					pr.Out.Header.Set("X-Forwarded-Port", v)
				}
			}
		},
	}
	return &rp, nil
}

func (p *TransparentBackend) isTrusted(hostport string) bool {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		hostport = host
	}
	ip, err := netip.ParseAddr(hostport)
	if err != nil {
		return false
	}
	if ip.Is4In6() {
		ip = ip.Unmap()
	}
	for _, p := range p.trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (p *TransparentBackend) Wait() error {
	if p.ctx == nil {
		return nil
	}
	<-p.ctx.Done()
	return nil
}

func (p *TransparentBackend) Close() error {
	return nil
}
