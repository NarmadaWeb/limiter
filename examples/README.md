# Fiber Limiter Examples [![Awesome](https://awesome.re/badge.svg)](https://awesome.re)

## Basic Example

```go
package main

import (
	"log"
	"time"

	"github.com/NarmadaWeb/limiter/v2"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	// Initialize with default in-memory store
	cfg := limiter.Config{
		MaxRequests: 5,
		Window:      1 * time.Minute,
		Algorithm:   "fixed-window",
	}

	l, err := limiter.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	app.Use(l.Middleware())

	app.Get("/", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"message":   "Hello World",
			"remaining": c.Get("X-RateLimit-Remaining"),
		})
	})

	log.Fatal(app.Listen(":3000"))
}
```

## Use With Redis

```go
package main

import (
	"time"

	"github.com/NarmadaWeb/limiter/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/redis/go-redis/v9"
)

func main() {
	app := fiber.New()

	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:6379", // or your Redis address
	})

	cfg := limiter.Config{
		RedisClient: rdb,
		MaxRequests: 100,
		Window:      5 * time.Minute,
		Algorithm:   "sliding-window",
	}

	l, err := limiter.New(cfg)
	if err != nil {
		panic(err)
	}

	app.Use(l.Middleware())

	app.Get("/data", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"data":      "Protected by Redis rate limiter",
			"remaining": c.Get("X-RateLimit-Remaining"),
		})
	})

	if err := app.Listen(":3000"); err != nil {
		panic(err)
	}
}
```

## Multiple Limiter

```go
package main

import (
	"log"
	"time"

	"github.com/NarmadaWeb/limiter/v2"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	// Global rate limiter (10 requests/minute)
	globalLimiter, err := limiter.New(limiter.Config{
		MaxRequests: 10,
		Window:      1 * time.Minute,
		Algorithm:   "sliding-window",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Strict API limiter (2 requests/second)
	apiLimiter, err := limiter.New(limiter.Config{
		MaxRequests: 2,
		Window:      1 * time.Second,
		Algorithm:   "sliding-window",
	})
	if err != nil {
		log.Fatal(err)
	}

	// Apply global limiter to all routes
	app.Use(globalLimiter.Middleware())

	// Public route
	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("Public endpoint (global rate limit only)")
	})

	// API group with additional rate limiting
	api := app.Group("/api", apiLimiter.Middleware())
	api.Get("/data", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"data":      "Sensitive API data",
			"remaining": c.Get("X-RateLimit-Remaining"),
		})
	})

	log.Fatal(app.Listen(":3000"))
}
```

## Error Handling

```go
package main

import (
	"log"
	"time"

	"github.com/NarmadaWeb/limiter/v2"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	cfg := limiter.Config{
		MaxRequests: 3,
		Window:      30 * time.Second,
		Algorithm:   "sliding-window",
		ErrorHandler: func(c *fiber.Ctx, err error) error {
			log.Printf("Rate limiter error: %v", err)
			return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
				"error":   "rate_limit_error",
				"message": "Unable to process rate limit",
			})
		},
		LimitReachedHandler: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{
				"error":   "rate_limit_exceeded",
				"message": "Slow down! You've made too many requests",
				"retry":   c.Get("X-RateLimit-Reset"),
			})
		},
	}

	l, err := limiter.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	app.Use(l.Middleware())

	app.Get("/api", func(c *fiber.Ctx) error {
		return c.SendString("API endpoint with custom error handling")
	})

	log.Fatal(app.Listen(":3000"))
}
```

## Custom Key

```go
package main

import (
	"log"
	"time"

	"github.com/NarmadaWeb/limiter/v2"
	"github.com/gofiber/fiber/v2"
)

func main() {
	app := fiber.New()

	cfg := limiter.Config{
		MaxRequests: 10,
		Window:      1 * time.Hour,
		Algorithm:   "token-bucket",
		KeyGenerator: func(c *fiber.Ctx) string {
			if apiKey := c.Get("X-API-Key"); apiKey != "" {
				return "api:" + apiKey
			}
			return "ip:" + c.IP() + ":" + c.Path()
		},
	}

	l, err := limiter.New(cfg)
	if err != nil {
		log.Fatal(err)
	}

	app.Use(l.Middleware())

	app.Get("/profile", func(c *fiber.Ctx) error {
		return c.SendString("Profile page - custom key rate limiting")
	})

	log.Fatal(app.Listen(":3000"))
}
```
