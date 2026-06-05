// Package ratelimit provides a simple token-bucket rate limiter for use
// by indago sources that need to respect per-source request rate limits.
package ratelimit

import (
	"context"
	"sync"
	"time"
)

// Limiter is a token-bucket rate limiter.
// Tokens refill at a fixed interval. Each call to Wait consumes one token.
type Limiter struct {
	mu       sync.Mutex
	tokens   int
	max      int
	interval time.Duration
	last     time.Time
}

// New creates a Limiter that allows up to maxTokens requests per interval.
// Example: New(10, time.Second) = 10 requests per second.
func New(maxTokens int, interval time.Duration) *Limiter {
	return &Limiter{
		tokens:   maxTokens,
		max:      maxTokens,
		interval: interval,
		last:     time.Now(),
	}
}

// Wait blocks until a token is available or ctx is cancelled.
// Returns ctx.Err() if the context is cancelled while waiting.
func (l *Limiter) Wait(ctx context.Context) error {
	for {
		l.mu.Lock()
		l.refill()
		if l.tokens > 0 {
			l.tokens--
			l.mu.Unlock()
			return nil
		}
		l.mu.Unlock()

		// Sleep one token's worth of time before retrying.
		sleep := l.interval / time.Duration(l.max)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(sleep):
		}
	}
}

// TryAcquire attempts to take a token without blocking.
// Returns true if a token was available, false otherwise.
func (l *Limiter) TryAcquire() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.refill()
	if l.tokens > 0 {
		l.tokens--
		return true
	}
	return false
}

// refill calculates how many tokens have regenerated since last and adds them
// up to max. Must be called with l.mu held.
func (l *Limiter) refill() {
	now := time.Now()
	elapsed := now.Sub(l.last)
	generated := int(elapsed / (l.interval / time.Duration(l.max)))
	if generated > 0 {
		l.tokens += generated
		if l.tokens > l.max {
			l.tokens = l.max
		}
		l.last = l.last.Add(time.Duration(generated) * (l.interval / time.Duration(l.max)))
	}
}
