# Echo Rate Limiting Example

This example demonstrates rate limiting with the Echo web framework.

## Code

```go
package main

import (
    "log"
    "net/http"
    "time"

    "github.com/NarmadaWeb/limiter/v2"
    "github.com/labstack/echo/v4"
)

func main() {
    e := echo.New()

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

    echoCfg := limiter.EchoConfig{
        ErrorHandler: func(c echo.Context, err error) error {
            log.Printf("Rate limiter error: %v", err)
            return c.JSON(http.StatusInternalServerError, map[string]string{
                "error":   "rate_limit_error",
                "message": "Unable to process rate limit",
            })
        },
        LimitReachedHandler: func(c echo.Context) error {
            return c.JSON(http.StatusTooManyRequests, map[string]string{
                "error":   "rate_limit_exceeded",
                "message": "Too many requests, please try again later",
            })
        },
    }

    e.Use(l.EchoMiddleware(echoCfg))

    e.GET("/", func(c echo.Context) error {
        return c.JSON(http.StatusOK, map[string]interface{}{
            "message":   "Hello World",
            "remaining": c.Response().Header().Get("X-RateLimit-Remaining"),
        })
    })

    e.Logger.Fatal(e.Start(":8080"))
}
```

## Running the Example

```bash
go run main.go
```

The server will start on port 8080. You can make requests to `http://localhost:8080/` and see the rate limiting in action.
