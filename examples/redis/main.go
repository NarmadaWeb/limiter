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
		Addr: "localhost:6379", // or your Redis address
	})

	cfg := limiter.Config{
		RedisClient: rdb,
		MaxRequests: 100,
		Window:      5 * time.Minute,
		Algorithm:   "sliding-window",
	}

	l, err := limiter.New(cfg)
	if err != nil {
		panic(err)
	}

	app.Use(l.Middleware())

	app.Get("/data", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{
			"data":      "Protected by Redis rate limiter",
			"remaining": c.Get("X-RateLimit-Remaining"),
		})
	})

	if err := app.Listen(":3000"); err != nil {
		panic(err)
	}
}
