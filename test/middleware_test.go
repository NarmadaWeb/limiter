package limiter_test

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/NarmadaWeb/limiter/v2"
	"github.com/gofiber/fiber/v2"
	"github.com/stretchr/testify/assert"
)

func TestLimiterMiddleware(t *testing.T) {
	app := fiber.New()

	// Setup limiter dengan limit 5 request per menit
	limiterCfg := limiter.Config{
		MaxRequests: 5,
		Window:      time.Minute,
		Algorithm:   "fixed-window",
	}
	l, err := limiter.New(limiterCfg)
	assert.NoError(t, err)

	app.Use(l.Middleware())

	app.Get("/", func(c *fiber.Ctx) error {
		return c.SendString("OK")
	})

	// Test request dalam limit
	for i := 0; i < 5; i++ {
		resp, err2 := app.Test(httptest.NewRequest(http.MethodGet, "/", nil))
		assert.NoError(t, err2)
		assert.Equal(t, http.StatusOK, resp.StatusCode)
	}

	// Test request melebihi limit
	resp, err := app.Test(httptest.NewRequest(http.MethodGet, "/", nil))
	assert.NoError(t, err)
	assert.Equal(t, http.StatusTooManyRequests, resp.StatusCode)
	assert.Equal(t, "0", resp.Header.Get("X-RateLimit-Remaining"))
}
