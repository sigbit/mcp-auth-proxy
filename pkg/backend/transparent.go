package backend

import (
	"context"
	"fmt"
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

func (p *TransparentBackend) Run(ctx context.Context) (http.Handler, error) {
	p.ctxLock.Lock()
	defer p.ctxLock.Unlock()
	if p.ctx != nil {
		return nil, fmt.Errorf("transparent backend is already running")
	}
	p.ctx = ctx
	rp := httputil.ReverseProxy{
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
