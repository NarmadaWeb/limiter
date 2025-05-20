package limiter

import (
	"errors"
)

var (
	ErrInvalidAlgorithm = errors.New("invalid rate limiting algorithm")
	ErrStorage          = errors.New("storage error")
	ErrRedisConnection  = errors.New("redis connection error")
	ErrInvalidConfig    = errors.New("invalid configuration")
)
