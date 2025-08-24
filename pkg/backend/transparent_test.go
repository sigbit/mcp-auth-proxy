package backend

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestTransparentBackend(t *testing.T) {
	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, c.Request.Header)
	})
	ts := httptest.NewServer(r)
	u, _ := url.Parse(ts.URL)

	be, err := NewTransparentBackend(zap.NewNop(), u, []string{})
	require.NoError(t, err)
	handler, err := be.Run(context.Background())
	require.NoError(t, err)
	require.NotNil(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var header http.Header
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &header))
	require.Equal(t, "192.0.2.1", header.Get(("X-Forwarded-For")))
	require.Equal(t, "example.com", header.Get(("X-Forwarded-Host")))
	require.Equal(t, "http", header.Get(("X-Forwarded-Proto")))
}

func TestTransparentBackendWithProxy(t *testing.T) {
	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, c.Request.Header)
	})
	ts := httptest.NewServer(r)
	u, _ := url.Parse(ts.URL)

	be, err := NewTransparentBackend(zap.NewNop(), u, []string{"0.0.0.0/0"})
	require.NoError(t, err)
	handler, err := be.Run(context.Background())
	require.NoError(t, err)
	require.NotNil(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "192.0.3.1")
	req.Header.Set("X-Forwarded-Host", "example.org")
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var header http.Header
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &header))
	require.Equal(t, "192.0.3.1, 192.0.2.1", header.Get(("X-Forwarded-For")))
	require.Equal(t, "example.org", header.Get(("X-Forwarded-Host")))
	require.Equal(t, "https", header.Get(("X-Forwarded-Proto")))
}

func TestTransparentBackendWithInvalidProxy(t *testing.T) {
	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, c.Request.Header)
	})
	ts := httptest.NewServer(r)
	u, _ := url.Parse(ts.URL)

	be, err := NewTransparentBackend(zap.NewNop(), u, []string{"1.1.1.1/32"})
	require.NoError(t, err)
	handler, err := be.Run(context.Background())
	require.NoError(t, err)
	require.NotNil(t, handler)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("X-Forwarded-For", "192.0.3.1")
	req.Header.Set("X-Forwarded-Host", "example.org")
	req.Header.Set("X-Forwarded-Proto", "https")
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	var header http.Header
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &header))
	require.Equal(t, "192.0.2.1", header.Get(("X-Forwarded-For")))
	require.Equal(t, "example.com", header.Get(("X-Forwarded-Host")))
	require.Equal(t, "http", header.Get(("X-Forwarded-Proto")))
}

func TestTransparentBackendRun(t *testing.T) {
	r := gin.New()
	r.GET("/", func(c *gin.Context) {
		c.JSON(http.StatusOK, c.Request.Header)
	})
	ts := httptest.NewServer(r)
	u, _ := url.Parse(ts.URL)

	be, err := NewTransparentBackend(zap.NewNop(), u, []string{})
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, err = be.Run(ctx)
	require.NoError(t, err)

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
