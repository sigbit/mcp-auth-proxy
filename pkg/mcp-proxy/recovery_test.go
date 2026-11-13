package mcpproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zaptest/observer"
)

func panicLogs(t *testing.T, dumpRequest bool) string {
	t.Helper()
	gin.SetMode(gin.TestMode)
	core, logs := observer.New(zap.DebugLevel)

	router := gin.New()
	router.Use(recoveryWithZap(zap.New(core), dumpRequest, func(c *gin.Context, _ any) {
		c.AbortWithStatus(http.StatusInternalServerError)
	}))
	router.GET("/mcp", func(*gin.Context) { panic("boom") })

	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer super-secret-token")
	req.Header.Set("Cookie", "session=super-secret-cookie")
	w := httptest.NewRecorder()
	router.ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}

	var sb strings.Builder
	for _, e := range logs.All() {
		sb.WriteString(e.Message)
		for _, f := range e.Context {
			sb.WriteString(" " + f.Key + "=" + f.String)
		}
	}
	return sb.String()
}

func TestRecoveryDoesNotLogCredentials(t *testing.T) {
	for _, dumpRequest := range []bool{false, true} {
		out := panicLogs(t, dumpRequest)
		if strings.Contains(out, "super-secret-token") || strings.Contains(out, "super-secret-cookie") {
			t.Fatalf("credentials leaked into logs (dumpRequest=%v): %s", dumpRequest, out)
		}
		if dumpRequest && !strings.Contains(out, "GET /mcp HTTP/1.1") {
			t.Fatalf("expected request dump in debug mode, got: %s", out)
		}
		if !dumpRequest && strings.Contains(out, "GET /mcp HTTP/1.1") {
			t.Fatalf("request dump present outside debug mode: %s", out)
		}
	}
}
