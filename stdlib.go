package limiter

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"strconv"
	"time"
)

type StdLibConfig struct {
	KeyGenerator        func(r *http.Request) string
	LimitReachedHandler http.HandlerFunc
	ErrorHandler        func(w http.ResponseWriter, r *http.Request, err error)
	Skipsuccessfull     bool
}

// StdLibMiddleware creates a standard net/http middleware.
// This works for Chi, Go Standard Library, and any framework compatible with http.Handler.
func (l *Limiter) StdLibMiddleware(cfg StdLibConfig) func(http.Handler) http.Handler {
	// Set defaults
	if cfg.KeyGenerator == nil {
		/**
		 * SECURITY FIX: HIGH – Improper Authentication (IP Spoofing)
		 * Risk: Attacker bypasses rate limits by providing fraudulent X-Forwarded-For headers.
		 * Attack vector: Spoofing headers to simulate requests from multiple distinct clients.
		 * Mitigation: Defaulted to RemoteAddr; delegated header trust to explicit user configuration.
		 * References: CWE-290, OWASP A07:2021-Identification and Authentication Failures
		 */
		cfg.KeyGenerator = func(r *http.Request) string {
			// Use RemoteAddr by default for security.
			// Users behind a proxy should provide a custom KeyGenerator that trusts specific headers.
			ip, _, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				return r.RemoteAddr
			}
			return ip
		}
	}
	if cfg.LimitReachedHandler == nil {
		cfg.LimitReachedHandler = func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "rate limit exceeded",
				"message": "Too many requests, please try again later",
			})
		}
	}
	if cfg.ErrorHandler == nil {
		/**
		 * SECURITY FIX: MEDIUM – Sensitive Data Exposure (Error Leak)
		 * Risk: Attacker gains knowledge of internal infrastructure or implementation details.
		 * Attack vector: Triggering rate-limit errors to reveal connection strings or file paths.
		 * Mitigation: Masked internal error messages with a generic "Internal rate limit error".
		 * References: CWE-209, OWASP A04:2021-Insecure Design
		 */
		cfg.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("Rate limiter error: %v", err)
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusInternalServerError)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"error":   "rate limit error",
				"message": "Internal rate limit error",
			})
		}
	}

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			key := cfg.KeyGenerator(r)

			allowed, remaining, reset, err := l.store.Take(r.Context(), key, l.config.MaxRequests, l.config.Window, l.config.Algorithm)
			if err != nil {
				cfg.ErrorHandler(w, r, err)
				return
			}

			w.Header().Set("X-RateLimit-Limit", strconv.Itoa(l.config.MaxRequests))
			w.Header().Set("X-RateLimit-Remaining", strconv.Itoa(remaining))
			w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(reset.Unix(), 10))
			w.Header().Set("RateLimit-Policy", fmt.Sprintf("%d;w=%d", l.config.MaxRequests, int(time.Minute.Seconds())))

			if !allowed {
				cfg.LimitReachedHandler(w, r)
				return
			}

			// To handle Skipsuccessfull, we need to capture the status code.
			// Wrap ResponseWriter
			ww := &responseWriter{ResponseWriter: w, code: http.StatusOK}
			next.ServeHTTP(ww, r)

			if cfg.Skipsuccessfull && ww.code < http.StatusBadRequest {
				_ = l.store.Rollback(r.Context(), key)
			}
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	code int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}
