# Custom Error Handling Example

This example demonstrates custom error handling and rate limit exceeded responses.

## Code

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
    }

    l, err := limiter.New(cfg)
    if err != nil {
        panic(err)
    }

    fiberCfg := limiter.FiberConfig{
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

    app.Use(l.FiberMiddleware(fiberCfg))

    app.Get("/api", func(c *fiber.Ctx) error {
        return c.SendString("API endpoint with custom error handling")
    })

    log.Fatal(app.Listen(":3000"))
}
```

## Running the Example

```bash
go run main.go
```

This example shows custom handlers for:

- `ErrorHandler`: Called when there's an internal error in the rate limiter
- `LimitReachedHandler`: Called when the rate limit is exceeded

Make more than 3 requests within 30 seconds to see the custom rate limit exceeded response.
