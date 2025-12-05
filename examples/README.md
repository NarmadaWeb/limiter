# Limiter Examples

This directory contains examples demonstrating various features of the rate limiter across different Go web frameworks.

## Examples

### Fiber Framework

- **[Basic](./basic/)** - Simple rate limiting with in-memory storage
- **[Redis](./redis/)** - Distributed rate limiting using Redis
- **[Multiple Limiters](./multiple-limiter/)** - Using different rate limiters for different routes
- **[Error Handling](./error-handling/)** - Custom error and rate limit exceeded handlers
- **[Custom Key](./custom-key/)** - Custom key generation for rate limiting buckets

### Gin Framework

- **[Gin Basic](./gin/)** - Rate limiting with Gin framework

### Echo Framework

- **[Echo Basic](./echo/)** - Rate limiting with Echo framework

### Standard Library / Chi

- **[StdLib/Chi](./stdlib/)** - Rate limiting with standard library and Chi router

Each example directory contains a `README.md` file with the complete code example and instructions for running it.
