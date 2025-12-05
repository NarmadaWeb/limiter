# Limiter

[![Go Report Card](https://goreportcard.com/badge/github.com/NarmadaWeb/limiter)](https://goreportcard.com/report/github.com/NarmadaWeb/limiter)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A high-performance rate limiting middleware supporting multiple Go web frameworks (Fiber, Gin, Echo, Chi, and standard library) with Redis and in-memory storage, implementing multiple rate-limiting algorithms.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
- [Basic Example](#basic-example-fiber)
- [With Redis](#with-redis-fiber)
- [Configuration Options](#configuration-options)
- [Response Headers](#response-headers)
- [Algorithms](#algorithms)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Features

- 🚀 **Multiple Algorithms**: Token Bucket, Sliding Window, and Fixed Window
- 🖥️ **Multi-Framework Support**: Fiber, Gin, Echo, Chi, and standard library
- 💾 **Storage Options**: Redis (for distributed systems) and in-memory (for single-instance)
- ⚡ **High Performance**: Minimal overhead with efficient algorithms
- 🔧 **Customizable**: Flexible key generation and response handling
- 📊 **RFC Compliance**: Standard `RateLimit` headers (RFC 6585)

## Installation

```bash
go get github.com/NarmadaWeb/limiter/v2
```

## Usage

The limiter supports multiple web frameworks. Choose the appropriate middleware method for your framework:

- **Fiber**: `l.FiberMiddleware(config)`
- **Gin**: `l.GinMiddleware(config)`
- **Echo**: `l.EchoMiddleware(config)`
- **StdLib**: `l.StdLibMiddleware(config)` (works with Chi, Gorilla Mux, etc.)

### Basic Example (Fiber)

```go
package main

import (
    "time"

    "github.com/gofiber/fiber/v2"
    "github.com/NarmadaWeb/limiter/v2"
)

func main() {
    app := fiber.New()

    // Initialize with default in-memory store
    limiterCfg := limiter.Config{
        MaxRequests: 100,
        Window:      1 * time.Minute,
        Algorithm:   "sliding-window",
    }

    l, err := limiter.New(limiterCfg)
    if err != nil {
        panic(err)
    }

    app.Use(l.FiberMiddleware(limiter.FiberConfig{}))

    app.Get("/", func(c *fiber.Ctx) error {
        return c.SendString("Hello, World!")
    })

    app.Listen(":3000")
}
```

### With Redis (Fiber)

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
        Addr: "localhost:6379",
    })

    limiterCfg := limiter.Config{
        RedisClient: rdb,
        MaxRequests: 200,
        Window:      5 * time.Minute,
        Algorithm:   "token-bucket",
    }

    l, err := limiter.New(limiterCfg)
    if err != nil {
        panic(err)
    }
    app.Use(l.FiberMiddleware(limiter.FiberConfig{}))

    app.Get("/", func(c *fiber.Ctx) error {
        return c.SendString("Hello with Redis!")
    })

    app.Listen(":3000")
}
```

### Gin Framework

```go
package main

import (
    "time"

    "github.com/NarmadaWeb/limiter/v2"
    "github.com/gin-gonic/gin"
)

func main() {
    r := gin.Default()

    limiterCfg := limiter.Config{
        MaxRequests: 100,
        Window:      1 * time.Minute,
        Algorithm:   "sliding-window",
    }

    l, err := limiter.New(limiterCfg)
    if err != nil {
        panic(err)
    }

    r.Use(l.GinMiddleware(limiter.GinConfig{}))

    r.GET("/", func(c *gin.Context) {
        c.JSON(200, gin.H{"message": "Hello from Gin!"})
    })

    r.Run(":8080")
}
```

### Echo Framework

```go
package main

import (
    "net/http"
    "time"

    "github.com/NarmadaWeb/limiter/v2"
    "github.com/labstack/echo/v4"
)

func main() {
    e := echo.New()

    limiterCfg := limiter.Config{
        MaxRequests: 100,
        Window:      1 * time.Minute,
        Algorithm:   "sliding-window",
    }

    l, err := limiter.New(limiterCfg)
    if err != nil {
        panic(err)
    }

    e.Use(l.EchoMiddleware(limiter.EchoConfig{}))

    e.GET("/", func(c echo.Context) error {
        return c.JSON(http.StatusOK, map[string]string{"message": "Hello from Echo!"})
    })

    e.Logger.Fatal(e.Start(":8080"))
}
```

### Standard Library / Chi Router

```go
package main

import (
    "encoding/json"
    "net/http"
    "time"

    "github.com/NarmadaWeb/limiter/v2"
    "github.com/go-chi/chi/v5"
)

func main() {
    r := chi.NewRouter()

    limiterCfg := limiter.Config{
        MaxRequests: 100,
        Window:      1 * time.Minute,
        Algorithm:   "sliding-window",
    }

    l, err := limiter.New(limiterCfg)
    if err != nil {
        panic(err)
    }

    r.Use(l.StdLibMiddleware(limiter.StdLibConfig{}))

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"message": "Hello from Chi!"})
    })

    http.ListenAndServe(":8080", r)
}
```

## Configuration Options

### Core Configuration

| Option                | Type                  | Description                                                                 |
|-----------------------|-----------------------|-----------------------------------------------------------------------------|
| `RedisClient`         | `*redis.Client`       | Redis client instance (optional)                                            |
| `RedisURL`            | `string`              | Redis connection URL (alternative to RedisClient)                           |
| `MaxRequests`         | `int`                 | Maximum allowed requests per window                                         |
| `Window`              | `time.Duration`       | Duration of the rate limit window (e.g., 1*time.Minute)                     |
| `Algorithm`           | `string`              | Rate limiting algorithm (`token-bucket`, `sliding-window`, `fixed-window`)  |

### Framework-Specific Configuration

Each framework has its own configuration struct with framework-specific handlers:

#### FiberConfig

| Option                | Type                  | Description                                                                 |
|-----------------------|-----------------------|-----------------------------------------------------------------------------|
| `KeyGenerator`        | `func(*fiber.Ctx) string` | Custom function to generate rate limit keys (default: client IP)         |
| `SkipSuccessful`      | `bool`                | Don't count successful requests (status < 400)                              |
| `LimitReachedHandler` | `fiber.Handler`       | Custom handler when limit is reached                                        |
| `ErrorHandler`        | `func(*fiber.Ctx, error) error` | Custom error handler for storage/configuration errors           |

#### GinConfig

| Option                | Type                  | Description                                                                 |
|-----------------------|-----------------------|-----------------------------------------------------------------------------|
| `KeyGenerator`        | `func(*gin.Context) string` | Custom function to generate rate limit keys (default: client IP)         |
| `SkipSuccessful`      | `bool`                | Don't count successful requests (status < 400)                              |
| `LimitReachedHandler` | `func(*gin.Context)`  | Custom handler when limit is reached                                        |
| `ErrorHandler`        | `func(*gin.Context, error)` | Custom error handler for storage/configuration errors           |

#### EchoConfig
| Option                | Type                  | Description                                                                 |
|-----------------------|-----------------------|-----------------------------------------------------------------------------|
| `KeyGenerator`        | `func(echo.Context) string` | Custom function to generate rate limit keys (default: real IP)           |
| `SkipSuccessful`      | `bool`                | Don't count successful requests (status < 400)                              |

| `LimitReachedHandler` | `func(echo.Context) error` | Custom handler when limit is reached                                        |
| `ErrorHandler`        | `func(echo.Context, error) error` | Custom error handler for storage/configuration errors           |
#### StdLibConfig
| Option                | Type                  | Description                                                                 |
|-----------------------|-----------------------|-----------------------------------------------------------------------------|
| `KeyGenerator`        | `func(*http.Request) string` | Custom function to generate rate limit keys (default: client IP)         |
| `SkipSuccessful`      | `bool`                | Don't count successful requests (status < 400)                              |
| `LimitReachedHandler` | `http.HandlerFunc`    | Custom handler when limit is reached                                        |
| `ErrorHandler`        | `func(http.ResponseWriter, *http.Request, error)` | Custom error handler for storage/configuration errors |

## Response Headers

The middleware adds these standard headers to responses:

- `X-RateLimit-Limit`: Maximum requests allowed
- `X-RateLimit-Remaining`: Remaining requests in current window
- `X-RateLimit-Reset`: Unix timestamp when limit resets
- `RateLimit-Policy`: Formal policy description

## Algorithms

1. **Token Bucket**
   - Smooth bursting allowed
   - Gradually refills tokens at steady rate
   - Good for evenly distributed loads

2. **Sliding Window**
   - Precise request counting
   - Tracks exact request timestamps
   - Prevents bursts at window edges

3. **Fixed Window**
   - Simple implementation

   - Counts requests per fixed interval
   - May allow bursts at window boundaries
## Examples
See the [examples directory](examples/) for complete implementations for all supported frameworks:

### Fiber Examples
- **[Basic](./examples/basic/)** - Simple rate limiting with in-memory storage

- **[Redis](./examples/redis/)** - Distributed rate limiting using Redis

- **[Multiple Limiters](./examples/multiple-limiter/)** - Using different rate limiters for different routes
- **[Error Handling](./examples/error-handling/)** - Custom error and rate limit exceeded handlers

- **[Custom Key](./examples/custom-key/)** - Custom key generation for rate limiting buckets
### Gin Examples
- **[Gin Basic](./examples/gin/)** - Rate limiting with Gin framework

### Echo Examples
- **[Echo Basic](./examples/echo/)** - Rate limiting with Echo framework

### Standard Library Examples
- **[StdLib/Chi](./examples/stdlib/)** - Rate limiting with standard library and Chi router

## Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT © NarmadaWeb - See [LICENSE](https://github.com/NarmadaWeb/limiter/blob/main/LICENSE) for details.
