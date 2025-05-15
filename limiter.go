// fiber limiter is a middleware limiter for fiber and simple to use
// easy to configuration

package limiter

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

type Config struct {
	// Redis Configuration for starting limiter
	RedisClient *redis.Client
	RedisURL    string

	// Rate Limiter configuration
	MaxRequests int
	Window      time.Duration

	// value "token-bucket", "sliding-window" and "fixed-window"
	Algorithm string

	KeyGenerator func(c *fiber.Ctx) string

	Skipsuccessfull     bool
	LimitReachedHandler fiber.Handler

	ErrorHandler func(c *fiber.Ctx, err error) error
}

type Limiter struct {
	store      Store
	config     Config
	ctx        context.Context
	cancelfunc context.CancelFunc
}

func New(config Config) (*Limiter, error) {
	if err := validateConfig(&config); err != nil {
		return nil, fmt.Errorf("invalid config: %w", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Initialize store
	store, err := initStore(ctx, config)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("store initialization failed: %w", err)
	}

	// Set defaults
	if config.KeyGenerator == nil {
		config.KeyGenerator = defaultKeyGenerator
	}

	if config.LimitReachedHandler == nil {
		config.LimitReachedHandler = defaultLimitReachedHandler
	}

	if config.ErrorHandler == nil {
		config.ErrorHandler = defaultErrorHandler
	}

	return &Limiter{
		store:      store,
		config:     config,
		ctx:        ctx,
		cancelfunc: cancel,
	}, nil
}

// Middleware returns the Fiber middleware handler
func (l *Limiter) Middleware() fiber.Handler {
	return func(c *fiber.Ctx) error {
		key := l.config.KeyGenerator(c)

		allowed, remaining, reset, err := l.store.Take(l.ctx, key, l.config.MaxRequests, l.config.Window, l.config.Algorithm)
		if err != nil {
			return l.config.ErrorHandler(c, err)
		}

		SetRateLimitHeaders(c, l.config.MaxRequests, remaining, reset)

		if !allowed {
			return l.config.LimitReachedHandler(c)
		}

		err = c.Next()

		if l.config.Skipsuccessfull && err == nil && c.Response().StatusCode() < fiber.StatusBadRequest {
			return l.store.Rollback(l.ctx, key)
		}

		return err
	}
}

func (l *Limiter) Close() error {
	l.cancelfunc()

	if closer, ok := l.store.(interface{ Close() error }); ok {
		return closer.Close()
	}
	return nil
}

// Helper functions
func validateConfig(cfg *Config) error {
	if cfg.MaxRequests <= 0 {
		return errors.New("maxRequests must be positive")
	}
	if cfg.Window <= 0 {
		return errors.New("window duration must be positive")
	}
	if !slices.Contains([]string{"token-bucket", "sliding-window", "fixed-window"}, cfg.Algorithm) {
		return errors.New("invalid algorithm")
	}
	return nil
}

func initStore(ctx context.Context, config Config) (Store, error) {
	switch {
	case config.RedisClient != nil:
		return NewRedisStore(config.RedisClient), nil
	case config.RedisURL != "":
		rdb := redis.NewClient(&redis.Options{Addr: config.RedisURL})
		if err := rdb.Ping(ctx).Err(); err != nil {
			return nil, fmt.Errorf("redis connection failed: %w", err)
		}
		return NewRedisStore(rdb), nil
	default:
		return NewMemoryStore(), nil
	}
}

func defaultKeyGenerator(c *fiber.Ctx) string {
	return c.IP()
}

func defaultLimitReachedHandler(c *fiber.Ctx) error {
	return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
		"error":   "rate limit exceeded",
		"message": "Too many requests, please try again later",
	})
}

func defaultErrorHandler(c *fiber.Ctx, err error) error {
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
		"error":   "rate limit error",
		"message": err.Error(),
	})
}

func SetRateLimitHeaders(c *fiber.Ctx, limit, remaining int, reset time.Time) {
	c.Set("X-RateLimit-Limit", strconv.Itoa(limit))
	c.Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
	c.Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
	c.Set("RateLimit-Policy", fmt.Sprintf("%d;w=%d", limit, int(time.Minute.Seconds())))
}
