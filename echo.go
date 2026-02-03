package limiter

import (
	"fmt"
	"log"
	"net/http"
	"strconv"
	"time"

	"github.com/labstack/echo/v4"
)

type EchoConfig struct {
	KeyGenerator        func(c echo.Context) string
	LimitReachedHandler func(c echo.Context) error
	ErrorHandler        func(c echo.Context, err error) error
	Skipsuccessfull     bool
}

func (l *Limiter) EchoMiddleware(cfg EchoConfig) echo.MiddlewareFunc {
	// Set defaults
	if cfg.KeyGenerator == nil {
		cfg.KeyGenerator = func(c echo.Context) string {
			return c.RealIP()
		}
	}
	if cfg.LimitReachedHandler == nil {
		cfg.LimitReachedHandler = func(c echo.Context) error {
			return c.JSON(http.StatusTooManyRequests, map[string]string{
				"error":   "rate limit exceeded",
				"message": "Too many requests, please try again later",
			})
		}
	}
	if cfg.ErrorHandler == nil {
		/**
		 * SECURITY FIX: MEDIUM – Sensitive Data Exposure (Error Leak)
		 * Risk: Attacker gains knowledge of internal infrastructure or implementation details.
		 * Attack vector: Triggering rate-limit errors to reveal connection strings or file paths.
		 * Mitigation: Masked internal error messages with a generic "Internal rate limit error".
		 * References: CWE-209, OWASP A04:2021-Insecure Design
		 */
		cfg.ErrorHandler = func(c echo.Context, err error) error {
			log.Printf("Rate limiter error: %v", err)
			return c.JSON(http.StatusInternalServerError, map[string]string{
				"error":   "rate limit error",
				"message": "Internal rate limit error",
			})
		}
	}

	return func(next echo.HandlerFunc) echo.HandlerFunc {
		return func(c echo.Context) error {
			key := cfg.KeyGenerator(c)

			allowed, remaining, reset, err := l.store.Take(l.ctx, key, l.config.MaxRequests, l.config.Window, l.config.Algorithm)
			if err != nil {
				return cfg.ErrorHandler(c, err)
			}

			c.Response().Header().Set("X-RateLimit-Limit", strconv.Itoa(l.config.MaxRequests))
			c.Response().Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			c.Response().Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
			c.Response().Header().Set("RateLimit-Policy", fmt.Sprintf("%d;w=%d", l.config.MaxRequests, int(time.Minute.Seconds())))

			if !allowed {
				return cfg.LimitReachedHandler(c)
			}

			err = next(c)

			if cfg.Skipsuccessfull && err == nil && c.Response().Status < http.StatusBadRequest {
				_ = l.store.Rollback(l.ctx, key)
			}

			return err
		}
	}
}
