# Fiber Limiter
[![Go Report Card](https://goreportcard.com/badge/github.com/NarmadaWeb/limiter)](https://goreportcard.com/report/github.com/NarmadaWeb/limiter)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

A high-performance rate limiting middleware for [Fiber](https://github.com/gofiber/fiber) with Redis and in-memory support, implementing multiple rate-limiting algorithms.

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
import "github.com/redis/go-redis/v9"

// ...

rdb := redis.NewClient(&redis.Options{
	Addr: "localhost:6379",
})

limiterCfg := limiter.Config{
	RedisClient: rdb,
	MaxRequests: 200,
	Window:      5 * time.Minute,
	Algorithm:   "token-bucket",
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

### 1. Token Bucket
- Smooth bursting allowed
- Gradually refills tokens at steady rate
- Good for evenly distributed loads

### 2. Sliding Window
- Precise request counting
- Tracks exact request timestamps
- Prevents bursts at window edges

### 3. Fixed Window
- Simple implementation
- Counts requests per fixed interval
- May allow bursts at window boundaries

## Examples

See the [examples directory](examples/) for:
- [Basic usage](examples/README.md/#basic-example)
- [Redis integration](examples/README.md/#use-with-redis)
- [Custom key generation](examples/README.md/#custom-key)
- [Error handling](examples/README.md/#error-handling)
- [Multiple limiters](examples/README.md/#multiple-limiter)

## Contributing

Pull requests are welcome! For major changes, please open an issue first to discuss what you'd like to change.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
