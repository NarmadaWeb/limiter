package limiter_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NarmadaWeb/limiter/v2"
	"github.com/redis/go-redis/v9"
	"github.com/stretchr/testify/assert"
)

func TestMemoryStore_DoS_Mitigation(t *testing.T) {
	m := limiter.NewMemoryStore()
	defer m.Close()
	ctx := context.Background()
	window := 1 * time.Hour
	maxRequests := 1000000

	// Pre-fill with many keys
	numKeys := 20000
	for i := 0; i < numKeys; i++ {
		m.Take(ctx, fmt.Sprintf("key-%d", i), maxRequests, window, "fixed-window")
	}

	// Measure time for 100 Take calls. O(N) would be slow.
	start := time.Now()
	for i := 0; i < 100; i++ {
		m.Take(ctx, "constant-key", maxRequests, window, "fixed-window")
	}
	elapsed := time.Since(start)

	t.Logf("Time for 100 Take calls with %d existing keys: %v", numKeys, elapsed)
	assert.Less(t, elapsed, 100*time.Millisecond, "Take is too slow, possible O(N) regression")
}

func TestStdLibMiddleware_IP_Spoofing_Mitigation(t *testing.T) {
	l, _ := limiter.New(limiter.Config{
		MaxRequests: 1,
		Window:      time.Minute,
		Algorithm:   "fixed-window",
	})

	handler := l.StdLibMiddleware(limiter.StdLibConfig{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// First request with spoofed IP
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.Header.Set("X-Forwarded-For", "1.1.1.1")
	req1.RemoteAddr = "2.2.2.2:1234"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Second request with same RemoteAddr but different spoofed IP
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.Header.Set("X-Forwarded-For", "1.1.1.2")
	req2.RemoteAddr = "2.2.2.2:1234"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)
	// It should be rate limited because RemoteAddr is the same
	assert.Equal(t, http.StatusTooManyRequests, w2.Code)
}

func TestError_Leak_Mitigation(t *testing.T) {
	// Use a redis client that will fail
	rdb := redis.NewClient(&redis.Options{
		Addr: "localhost:1",
	})
	l, _ := limiter.New(limiter.Config{
		RedisClient: rdb,
		MaxRequests: 1,
		Window:      time.Minute,
		Algorithm:   "fixed-window",
	})

	handler := l.StdLibMiddleware(limiter.StdLibConfig{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	assert.NoError(t, err)
	assert.Equal(t, "Internal rate limit error", resp["message"])
	assert.NotContains(t, resp["message"], "connection refused")
}
