package limiter

import (
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
)

type FiberConfig struct {
	KeyGenerator        func(c *fiber.Ctx) string
	LimitReachedHandler fiber.Handler
	ErrorHandler        func(c *fiber.Ctx, err error) error
	Skipsuccessfull     bool
}

func (l *Limiter) FiberMiddleware(cfg FiberConfig) fiber.Handler {
	// Set defaults
	if cfg.KeyGenerator == nil {
		cfg.KeyGenerator = defaultFiberKeyGenerator
	}
	if cfg.LimitReachedHandler == nil {
		cfg.LimitReachedHandler = defaultFiberLimitReachedHandler
	}
	if cfg.ErrorHandler == nil {
		cfg.ErrorHandler = defaultFiberErrorHandler
	}

	return func(c *fiber.Ctx) error {
		key := cfg.KeyGenerator(c)

		allowed, remaining, reset, err := l.store.Take(l.ctx, key, l.config.MaxRequests, l.config.Window, l.config.Algorithm)
		if err != nil {
			return cfg.ErrorHandler(c, err)
		}

		setFiberRateLimitHeaders(c, l.config.MaxRequests, remaining, reset)

		if !allowed {
			return cfg.LimitReachedHandler(c)
		}

		err = c.Next()

		if cfg.Skipsuccessfull && err == nil && c.Response().StatusCode() < fiber.StatusBadRequest {
			return l.store.Rollback(l.ctx, key)
		}

		return err
	}
}

// Keep the old Middleware method for backward compatibility if possible?
// No, the Config struct changed so backward compatibility is broken anyway.

func defaultFiberKeyGenerator(c *fiber.Ctx) string {
	return c.IP()
}

func defaultFiberLimitReachedHandler(c *fiber.Ctx) error {
	return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
		"error":   "rate limit exceeded",
		"message": "Too many requests, please try again later",
	})
}

func defaultFiberErrorHandler(c *fiber.Ctx, err error) error {
	/**
	 * SECURITY FIX: MEDIUM – Sensitive Data Exposure (Error Leak)
	 * Risk: Attacker gains knowledge of internal infrastructure or implementation details.
	 * Attack vector: Triggering rate-limit errors to reveal connection strings or file paths.
	 * Mitigation: Masked internal error messages with a generic "Internal rate limit error".
	 * References: CWE-209, OWASP A04:2021-Insecure Design
	 */
	log.Printf("Rate limiter error: %v", err)
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error":   "rate limit error",
		"message": "Internal rate limit error",
	})
}

func setFiberRateLimitHeaders(c *fiber.Ctx, limit, remaining int, reset time.Time) {
	c.Set("X-RateLimit-Limit", strconv.Itoa(limit))
	c.Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
	c.Set("RateLimit-Policy", fmt.Sprintf("%d;w=%d", limit, int(time.Minute.Seconds())))
}
