# Gin Rate Limiting Example

This example demonstrates rate limiting with the Gin web framework.

## Code

```go
package main

import (
    "log"
    "time"

    "github.com/NarmadaWeb/limiter/v2"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

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

    ginCfg := limiter.GinConfig{
        ErrorHandler: func(c *gin.Context, err error) {
            log.Printf("Rate limiter error: %v", err)
            c.JSON(500, gin.H{
                "error":   "rate_limit_error",
                "message": "Unable to process rate limit",
            })
        },
        LimitReachedHandler: func(c *gin.Context) {
            c.JSON(429, gin.H{
                "error":   "rate_limit_exceeded",
                "message": "Too many requests, please try again later",
            })
        },
    }

    r.Use(l.GinMiddleware(ginCfg))

    r.GET("/", func(c *gin.Context) {
        c.JSON(200, gin.H{
            "message":   "Hello World",
            "remaining": c.GetHeader("X-RateLimit-Remaining"),
        })
    })

    r.Run(":8080")
}
```

## Running the Example

```bash
go run main.go
```

The server will start on port 8080. You can make requests to `http://localhost:8080/` and see the rate limiting in action.
