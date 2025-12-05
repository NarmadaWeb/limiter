# Custom Key Generation Example

This example demonstrates custom key generation for rate limiting based on API keys or other request attributes.

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
        MaxRequests: 10,
        Window:      1 * time.Hour,
        Algorithm:   "token-bucket",
    }

    l, err := limiter.New(cfg)
    if err != nil {
        panic(err)
    }

    fiberCfg := limiter.FiberConfig{
        KeyGenerator: func(c *fiber.Ctx) string {
            if apiKey := c.Get("X-API-Key"); apiKey != "" {
                return "api:" + apiKey
            }
            return "ip:" + c.IP() + ":" + c.Path()
        },
    }

    app.Use(l.FiberMiddleware(fiberCfg))

    app.Get("/profile", func(c *fiber.Ctx) error {
        return c.SendString("Profile page - custom key rate limiting")
    })

    log.Fatal(app.Listen(":3000"))
}
```

## Running the Example

```bash
go run main.go
```

This example uses a custom key generator that:

- Uses API key from `X-API-Key` header if present (prefixing with "api:")
- Falls back to IP address + path combination if no API key

Test with different API keys or IP addresses to see separate rate limiting buckets.
