To fix the MD010 errors caused by hard tabs in the README.md file, replace all tab characters with spaces in the code blocks and other affected sections. Here's the corrected README content:

```markdown
# Limiter Middleware for gofiber

[![Go Report Card](https://goreportcard.com/badge/github.com/NarmadaWeb/limiter)](https://goreportcard.com/report/github.com/NarmadaWeb/limiter)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](https://opensource.org/licenses/MIT)

A high-performance rate limiting middleware for [Fiber](https://github.com/gofiber/fiber) with Redis and in-memory support, implementing multiple rate-limiting algorithms.

## Table of Contents

- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Example](#basic-example)
  - [With Redis](#with-redis)
- [Configuration Options](#configuration-options)
- [Response Headers](#response-headers)
- [Algorithms](#algorithms)
- [Examples](#examples)
- [Contributing](#contributing)
- [License](#license)

## Features

- 🚀 **Multiple Algorithms**: Token Bucket, Sliding Window, and Fixed Window
- 💾 **Storage Options**: Redis (for distributed systems) and in-memory (for single-instance)
- ⚡ **High Performance**: Minimal overhead with efficient algorithms
- 🔧 **Customizable**: Flexible key generation and response handling
- 📊 **RFC Compliance**: Standard `RateLimit` headers (RFC 6585)

## Installation

```bash
go get github.com/NarmadaWeb/limiter/v2
```

## Usage

### Basic Example

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

    app.Use(l.Middleware())

    app.Get("/", func(c *fiber.Ctx) error {
        return c.SendString("Hello, World!")
    })

    app.Listen(":3000")
}
```

### With Redis

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
    app.Use(l.Middleware())

    app.Get("/", func(c *fiber.Ctx) error {
        return c.SendString("Hello with Redis!")
    })

    app.Listen(":3000")
}
```

## Configuration Options

| Option                | Type                  | Description                                                                 |
|-----------------------|-----------------------|-----------------------------------------------------------------------------|
| `RedisClient`         | `*redis.Client`       | Redis client instance (optional)                                            |
| `RedisURL`            | `string`              | Redis connection URL (alternative to RedisClient)                           |
| `MaxRequests`         | `int`                 | Maximum allowed requests per window                                         |
| `Window`              | `time.Duration`       | Duration of the rate limit window (e.g., 1*time.Minute)                     |
| `Algorithm`           | `string`              | Rate limiting algorithm (`token-bucket`, `sliding-window`, `fixed-window`)  |
| `KeyGenerator`        | `func(*fiber.Ctx) string` | Custom function to generate rate limit keys (default: client IP)         |
| `SkipSuccessful`      | `bool`                | Don't count successful requests (status < 400)                              |
| `LimitReachedHandler` | `fiber.Handler`       | Custom handler when limit is reached                                        |
| `ErrorHandler`        | `func(*fiber.Ctx, error) error` | Custom error handler for storage/configuration errors           |

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

See the [examples directory](examples/) for more implementations:

1. Basic usage
2. Redis integration
3. Custom key generation
4. Error handling
5. Multiple limiters

## Contributing

We welcome contributions! Please see our [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

MIT © NarmadaWeb - See [LICENSE](https://github.com/NarmadaWeb/limiter/blob/main/LICENSE) for details.
