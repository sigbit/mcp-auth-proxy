package mcpproxy

import (
	"net"
	"net/http/httputil"
	"os"
	"runtime/debug"
	"strings"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// sensitiveHeaders are masked in any request dump we emit.
var sensitiveHeaders = []string{"authorization:", "cookie:", "proxy-authorization:"}

// redactRequestDump masks credential-bearing headers in a raw HTTP request dump.
func redactRequestDump(dump string) string {
	lines := strings.Split(dump, "\r\n")
	for i, line := range lines {
		lower := strings.ToLower(line)
		for _, h := range sensitiveHeaders {
			if strings.HasPrefix(lower, h) {
				lines[i] = line[:len(h)-1] + ": [REDACTED]"
				break
			}
		}
	}
	return strings.Join(lines, "\r\n")
}

// recoveryWithZap replaces ginzap.CustomRecoveryWithZap, which dumps the raw
// request, Authorization header and all, on every panic and broken pipe.
// The dump is emitted only in debug mode, and always with credentials masked.
func recoveryWithZap(logger *zap.Logger, dumpRequest bool, recovery gin.RecoveryFunc) gin.HandlerFunc {
	return func(c *gin.Context) {
		defer func() {
			err := recover()
			if err == nil {
				return
			}

			fields := []zap.Field{zap.Any("error", err)}
			if dumpRequest {
				dump, _ := httputil.DumpRequest(c.Request, false)
				fields = append(fields, zap.String("request", redactRequestDump(string(dump))))
			}

			// A dead connection is not worth a stack trace, and nothing can be
			// written back to it.
			if brokenPipe(err) {
				logger.Error(c.Request.URL.Path, fields...)
				if e, ok := err.(error); ok {
					_ = c.Error(e)
				}
				c.Abort()
				return
			}

			fields = append(fields, zap.String("stack", string(debug.Stack())))
			logger.Error("[Recovery from panic]", fields...)
			recovery(c, err)
		}()
		c.Next()
	}
}

func brokenPipe(err any) bool {
	ne, ok := err.(*net.OpError)
	if !ok {
		return false
	}
	se, ok := ne.Err.(*os.SyscallError)
	if !ok {
		return false
	}
	msg := strings.ToLower(se.Error())
	return strings.Contains(msg, "broken pipe") || strings.Contains(msg, "connection reset by peer")
}
