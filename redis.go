package limiter

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

type RedisStore struct {
	client *redis.Client
	prefix string
}

func NewRedisStore(client *redis.Client) *RedisStore {
	return &RedisStore{
		client: client,
		prefix: "rate_limit:",
	}
}

func (r *RedisStore) Take(ctx context.Context, key string, maxRequests int, window time.Duration, algorithm string) (bool, int, time.Time, error) {
	fullKey := r.prefix + algorithm + ":" + key
	now := time.Now()
	reset := now.Add(window)

	switch algorithm {
	case "token-bucket":
		return r.tokenBucketTake(ctx, fullKey, maxRequests, window, now, reset)
	case "sliding-window":
		return r.slidingWindowTake(ctx, fullKey, maxRequests, window, now, reset)
	default: // fixed-window
		return r.fixedWindowTake(ctx, fullKey, maxRequests, window, now, reset)
	}
}

func (r *RedisStore) tokenBucketTake(ctx context.Context, key string, maxRequests int, window time.Duration, now, reset time.Time) (bool, int, time.Time, error) {
	if err := r.ensureKeyType(ctx, key, "hash"); err != nil {
		return false, 0, reset, err
	}

	script := `
	local key = KEYS[1]
	local now = tonumber(ARGV[1])
	local window = tonumber(ARGV[2])
	local maxRequests = tonumber(ARGV[3])

	-- Initialize if not exists
	if redis.call("EXISTS", key) == 0 then
		redis.call("HMSET", key, "tokens", maxRequests, "lastUpdate", now)
		redis.call("EXPIRE", key, window)
		return {1, maxRequests-1, now+window}
	end

	local bucket = redis.call("HMGET", key, "tokens", "lastUpdate")
	local tokens = tonumber(bucket[1])
	local lastUpdate = tonumber(bucket[2])

	local fillRate = maxRequests / window
	local timePassed = now - lastUpdate
	tokens = math.min(maxRequests, tokens + timePassed * fillRate)

	if tokens < 1 then
		return {0, 0, lastUpdate + (1 - tokens) / fillRate}
	end

	tokens = tokens - 1
	redis.call("HMSET", key, "tokens", tokens, "lastUpdate", now)
	redis.call("EXPIRE", key, window)
	return {1, tokens, now + (maxRequests - tokens) / fillRate}
	`

	results, err := r.client.Eval(ctx, script, []string{key}, now.Unix(), window.Seconds(), maxRequests).Slice()
	if err != nil {
		return false, 0, reset, fmt.Errorf("token bucket script failed: %w", err)
	}

	allowed := results[0].(int64) == 1
	remaining := int(results[1].(int64))
	resetTime := time.Unix(results[2].(int64), 0)

	return allowed, remaining, resetTime, nil
}

func (r *RedisStore) slidingWindowTake(ctx context.Context, key string, maxRequests int, window time.Duration, now, reset time.Time) (bool, int, time.Time, error) {
	// Cleanup any existing key of wrong type
	if err := r.ensureKeyType(ctx, key, "zset"); err != nil {
		return false, 0, reset, err
	}

	script := `
	local key = KEYS[1]
	local now = tonumber(ARGV[1])
	local window = tonumber(ARGV[2])
	local maxRequests = tonumber(ARGV[3])

	-- Remove old entries
	redis.call("ZREMRANGEBYSCORE", key, 0, now - window)
	local current = redis.call("ZCARD", key)

	if current >= maxRequests then
		local oldest = redis.call("ZRANGE", key, 0, 0, "WITHSCORES")
		if #oldest == 0 then
			return {0, 0, now + window}
		end
		return {0, maxRequests - current, oldest[2] + window}
	end

	-- Add new entry
	redis.call("ZADD", key, now, now)
	redis.call("EXPIRE", key, window)
	return {1, maxRequests - current - 1, now + window}
	`

	results, err := r.client.Eval(ctx, script, []string{key}, now.Unix(), window.Seconds(), maxRequests).Slice()
	if err != nil {
		return false, 0, reset, fmt.Errorf("sliding window script failed: %w", err)
	}

	allowed := results[0].(int64) == 1
	remaining := int(results[1].(int64))
	resetUnix := results[2].(int64)

	return allowed, remaining, time.Unix(resetUnix, 0), nil
}

func (r *RedisStore) fixedWindowTake(ctx context.Context, key string, maxRequests int, window time.Duration, now, reset time.Time) (bool, int, time.Time, error) {
	// Cleanup any existing key of wrong type
	if err := r.ensureKeyType(ctx, key, "string"); err != nil {
		return false, 0, reset, err
	}

	script := `
	local key = KEYS[1]
	local window = tonumber(ARGV[1])
	local maxRequests = tonumber(ARGV[2])

	local current = tonumber(redis.call("GET", key) or "0")

	if current >= maxRequests then
		return {0, maxRequests - current, redis.call("TTL", key)}
	end

	redis.call("INCR", key)
	if current == 0 then
		redis.call("EXPIRE", key, window)
	end
	return {1, maxRequests - current - 1, window}
	`

	results, err := r.client.Eval(ctx, script, []string{key}, window.Seconds(), maxRequests).Slice()
	if err != nil {
		return false, 0, reset, fmt.Errorf("fixed window script failed: %w", err)
	}

	allowed := results[0].(int64) == 1
	remaining := int(results[1].(int64))
	ttl := time.Duration(results[2].(int64)) * time.Second

	return allowed, remaining, now.Add(ttl), nil
}

// ensureKeyType checks and converts key type if needed
func (r *RedisStore) ensureKeyType(ctx context.Context, key, expectedType string) error {
	actualType, err := r.client.Type(ctx, key).Result()
	if err != nil {
		return fmt.Errorf("failed to check key type: %w", err)
	}

	// Key doesn't exist or is already correct type
	if actualType == "none" || actualType == expectedType {
		return nil
	}

	// Delete key if wrong type
	if err := r.client.Del(ctx, key).Err(); err != nil {
		return fmt.Errorf("failed to delete wrong type key: %w", err)
	}

	return nil
}

func (r *RedisStore) Rollback(ctx context.Context, key string) error {
	// Try all possible key types
	_, err := r.client.Decr(ctx, r.prefix+"fixed-window:"+key).Result()
	if err == nil {
		return nil
	}

	_, err = r.client.HIncrBy(ctx, r.prefix+"token-bucket:"+key, "tokens", 1).Result()
	if err == nil {
		return nil
	}

	// For sliding window, we can't reliably rollback
	return nil
}

func (r *RedisStore) Get(ctx context.Context, key string) (int, error) {
	// Check all possible key types
	if val, err := r.client.Get(ctx, r.prefix+"fixed-window:"+key).Int(); err == nil {
		return val, nil
	}

	if val, err := r.client.HGet(ctx, r.prefix+"token-bucket:"+key, "tokens").Int(); err == nil {
		return val, nil
	}

	if val, err := r.client.ZCard(ctx, r.prefix+"sliding-window:"+key).Result(); err == nil {
		return int(val), nil
	}

	return 0, nil
}

func (r *RedisStore) Set(ctx context.Context, key string, value int, expiration time.Duration) error {
	// Not implemented for multiple algorithms
	return fmt.Errorf("Set operation not supported for RedisStore")
}

func (r *RedisStore) Close() error {
	return r.client.Close()
}
