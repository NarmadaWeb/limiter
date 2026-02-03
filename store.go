package limiter

import (
	"context"
	"sync"
	"time"
)

/**
 * SECURITY FIX: HIGH – Algorithmic Complexity (DoS)
 * Risk: Attacker can exhaust server CPU by generating many unique rate-limit keys.
 * Attack vector: Large-scale request flood with spoofed identifiers forces O(N) map traversal.
 * Mitigation: Replaced full-map scan with localized cleanup and background janitor.
 * References: CWE-400, OWASP A05:2021-Security Misconfiguration (Performance DoS)
 */

// Store defines the interface for limiter
// Store have 4 values Take, Rollback, Get and Set
type Store interface {
	Take(ctx context.Context, key string, maxRequests int, window time.Duration, algorithm string) (bool, int, time.Time, error)
	Rollback(ctx context.Context, key string) error
	Get(ctx context.Context, key string) (int, error)
	Set(ctx context.Context, key string, value int, expiration time.Duration) error
}

type MemoryStore struct {
	mu      sync.Mutex
	entries map[string]*MemoryEntries
	stop    chan struct{}
}

type MemoryEntries struct {
	count     int
	expiresAt time.Time
}

func NewMemoryStore() *MemoryStore {
	m := &MemoryStore{
		entries: make(map[string]*MemoryEntries),
		stop:    make(chan struct{}),
	}
	go m.cleaner()
	return m
}

func (m *MemoryStore) cleaner() {
	ticker := time.NewTicker(1 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			m.cleanup()
		case <-m.stop:
			return
		}
	}
}

func (m *MemoryStore) cleanup() {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	for k, v := range m.entries {
		if now.After(v.expiresAt) {
			delete(m.entries, k)
		}
	}
}

func (m *MemoryStore) Take(ctx context.Context, key string, maxRequests int, window time.Duration, algorithm string) (bool, int, time.Time, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	now := time.Now()
	reset := now.Add(window)

	entry, exists := m.entries[key]
	if exists && now.After(entry.expiresAt) {
		delete(m.entries, key)
		exists = false
	}

	if !exists {
		m.entries[key] = &MemoryEntries{
			count:     1,
			expiresAt: reset,
		}
		return true, maxRequests - 1, reset, nil
	}

	if entry.count >= maxRequests {
		return false, 0, entry.expiresAt, nil
	}

	entry.count++
	return true, maxRequests - entry.count, entry.expiresAt, nil
}

func (m *MemoryStore) Rollback(ctx context.Context, key string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, exists := m.entries[key]; exists {
		entry.count--
		if entry.count <= 0 {
			delete(m.entries, key)
		}
	}
	return nil
}

func (m *MemoryStore) Get(ctx context.Context, key string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if entry, exists := m.entries[key]; exists {
		return entry.count, nil
	}
	return 0, nil
}

func (m *MemoryStore) Set(ctx context.Context, key string, value int, expiration time.Duration) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.entries[key] = &MemoryEntries{
		count:     value,
		expiresAt: time.Now().Add(expiration),
	}
	return nil
}

func (m *MemoryStore) Close() error {
	select {
	case <-m.stop:
		// Already closed
	default:
		close(m.stop)
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	m.entries = make(map[string]*MemoryEntries)
	return nil
}
