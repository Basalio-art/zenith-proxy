package middleware

import (
	"context"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func RequestID() gin.HandlerFunc {
	return func(c *gin.Context) {
		rid := c.GetHeader("X-Request-ID")
		if rid == "" {
			rid = uuid.New().String()
		}
		c.Set("request_id", rid)
		c.Header("X-Request-ID", rid)
		c.Next()
	}
}

func Logger() gin.HandlerFunc {
	return gin.LoggerWithFormatter(func(param gin.LogFormatterParams) string {
		return ""
	})
}

func Recovery() gin.HandlerFunc {
	return gin.CustomRecovery(func(c *gin.Context, recovered any) {
		c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{
			"error":       "internal_error",
			"request_id":  c.GetString("request_id"),
		})
	})
}

func CORS(allowedOrigins string) gin.HandlerFunc {
	return func(c *gin.Context) {
		origin := c.Request.Header.Get("Origin")
		if allowedOrigins == "*" {
			c.Header("Access-Control-Allow-Origin", "*")
		} else if origin != "" {
			// In production, parse allowedOrigins and check
			c.Header("Access-Control-Allow-Origin", origin)
			c.Header("Vary", "Origin")
		}

		c.Header("Access-Control-Allow-Methods", "GET, HEAD, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Range, If-Range, Accept, Accept-Language, Origin, Content-Type, Authorization")
		c.Header("Access-Control-Expose-Headers", "Content-Length, Content-Range, Accept-Ranges, Content-Type, ETag, Last-Modified, Cache-Control, X-Proxy-Range")
		c.Header("Access-Control-Max-Age", "86400")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}

func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("X-Content-Type-Options", "nosniff")
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		// Do NOT set X-Frame-Options globally; embed/player pages allow framing via CSP
		// Cache-Control for API/manifest responses; media responses set their own
		c.Header("Cache-Control", "no-store, no-cache, must-revalidate")
		c.Next()
	}
}

// AllowFraming adds CSP frame-ancestors * for HTML player pages (iframe embed support)
func AllowFraming() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Content-Security-Policy", "frame-ancestors *")
		c.Next()
	}
}

func RateLimit(maxGlobal int) gin.HandlerFunc {
	sem := make(chan struct{}, maxGlobal)
	return func(c *gin.Context) {
		select {
		case sem <- struct{}{}:
			c.Next()
			<-sem
		default:
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"error":      "server_busy",
				"retry_after": 5,
			})
		}
	}
}

func Timeout(d time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		ctx, cancel := context.WithTimeout(c.Request.Context(), d)
		defer cancel()
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}