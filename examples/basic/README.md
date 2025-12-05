# Basic Rate Limiting Example

This example demonstrates basic rate limiting with the Fiber limiter using in-memory storage.

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

    // Initialize with default in-memory store
    cfg := limiter.Config{
        MaxRequests: 5,
        Window:      1 * time.Minute,
        Algorithm:   "fixed-window",
    }

    l, err := limiter.New(cfg)
    if err != nil {
        panic(err)
    }

    app.Use(l.FiberMiddleware(limiter.FiberConfig{}))

    app.Get("/", func(c *fiber.Ctx) error {
        return c.JSON(fiber.Map{
            "message":   "Hello World",
            "remaining": c.Get("X-RateLimit-Remaining"),
        })
    })

    log.Fatal(app.Listen(":3000"))
}
```

## Running the Example

```bash
go run main.go
```

The server will start on port 3000. You can make requests to `http://localhost:3000/` and see the rate limiting in action. The `X-RateLimit-Remaining` header will show how many requests you have left in the current window.
