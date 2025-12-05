# Standard Library Rate Limiting Example

This example demonstrates rate limiting with Go's standard library and frameworks compatible with `http.Handler`, such as Chi router.

## Code

```go
package main

import (
    "encoding/json"
    "log"
    "net/http"
    "time"

    "github.com/NarmadaWeb/limiter/v2"
    "github.com/go-chi/chi/v5"
)

func main() {
    r := chi.NewRouter()

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

    stdCfg := limiter.StdLibConfig{
        ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
            log.Printf("Rate limiter error: %v", err)
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusInternalServerError)
            json.NewEncoder(w).Encode(map[string]string{
                "error":   "rate_limit_error",
                "message": "Unable to process rate limit",
            })
        },
        LimitReachedHandler: func(w http.ResponseWriter, r *http.Request) {
            w.Header().Set("Content-Type", "application/json")
            w.WriteHeader(http.StatusTooManyRequests)
            json.NewEncoder(w).Encode(map[string]string{
                "error":   "rate_limit_exceeded",
                "message": "Too many requests, please try again later",
            })
        },
    }

    r.Use(l.StdLibMiddleware(stdCfg))

    r.Get("/", func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]interface{}{
            "message":   "Hello World",
            "remaining": r.Header.Get("X-RateLimit-Remaining"),
        })
    })

    log.Println("Server starting on :8080")
    http.ListenAndServe(":8080", r)
}
```

## Running the Example

```bash
go run main.go
```

The server will start on port 8080. You can make requests to `http://localhost:8080/` and see the rate limiting in action.

## Alternative: Using with Standard Library Only

If you want to use it with Go's standard `http` package without Chi:

```go
func main() {
    // ... same limiter setup ...

    http.Handle("/", l.StdLibMiddleware(limiter.StdLibConfig{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
        w.Header().Set("Content-Type", "application/json")
        json.NewEncoder(w).Encode(map[string]string{"message": "Hello World"})
    })))

    log.Println("Server starting on :8080")
    http.ListenAndServe(":8080", nil)
}
```
