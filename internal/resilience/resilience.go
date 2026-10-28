// Package resilience implements UTS-GO-106: retry with exponential backoff and jitter,
// per-attempt timeouts, permanent-error short-circuiting and a circuit breaker.
package resilience

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"time"
)

// ---------- permanent errors ----------

type permanent struct{ error }

func (p permanent) Unwrap() error { return p.error }

// Permanent marks an error as non-retryable (e.g. HTTP 4xx, validation failures).
func Permanent(err error) error {
	if err == nil {
		return nil
	}
	return permanent{err}
}

func IsPermanent(err error) bool {
	var p permanent
	return errors.As(err, &p)
}

// ---------- retry ----------

type RetryConfig struct {
	MaxAttempts       int           // total attempts including the first (default 3)
	BaseDelay         time.Duration // first backoff (default 200ms)
	MaxDelay          time.Duration // backoff cap (default 5s)
	PerAttemptTimeout time.Duration // 0 = no per-attempt deadline
	Jitter            bool          // randomise each delay within [d/2, d] to avoid thundering herds
	// Sleep is replaceable in tests. It must return early with ctx.Err() when ctx is done.
	Sleep func(ctx context.Context, d time.Duration) error
	// OnRetry is invoked before each wait; use it for logging/metrics.
	OnRetry func(attempt int, err error, next time.Duration)
}

func (c RetryConfig) withDefaults() RetryConfig {
	if c.MaxAttempts <= 0 {
		c.MaxAttempts = 3
	}
	if c.BaseDelay <= 0 {
		c.BaseDelay = 200 * time.Millisecond
	}
	if c.MaxDelay <= 0 {
		c.MaxDelay = 5 * time.Second
	}
	if c.Sleep == nil {
		c.Sleep = sleepCtx
	}
	return c
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c RetryConfig) backoff(attempt int) time.Duration {
	d := c.BaseDelay << (attempt - 1)
	if d <= 0 || d > c.MaxDelay { // d <= 0 guards shift overflow
		d = c.MaxDelay
	}
	if c.Jitter {
		half := int64(d / 2)
		if half > 0 {
			d = time.Duration(half + rand.Int64N(half+1))
		}
	}
	return d
}

// Do runs fn until it succeeds, returns a permanent error, the attempts are exhausted or ctx ends.
// Each attempt receives its own context carrying PerAttemptTimeout, so a hung downstream call
// cannot consume the whole retry budget.
func Do(ctx context.Context, cfg RetryConfig, fn func(ctx context.Context) error) error {
	cfg = cfg.withDefaults()
	var last error
	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return wrapCtx(err, last)
		}
		actx, cancel := ctx, context.CancelFunc(func() {})
		if cfg.PerAttemptTimeout > 0 {
			actx, cancel = context.WithTimeout(ctx, cfg.PerAttemptTimeout)
		}
		err := fn(actx)
		cancel()
		if err == nil {
			return nil
		}
		last = err
		if IsPermanent(err) {
			return err
		}
		if attempt == cfg.MaxAttempts {
			break
		}
		delay := cfg.backoff(attempt)
		if cfg.OnRetry != nil {
			cfg.OnRetry(attempt, err, delay)
		}
		if serr := cfg.Sleep(ctx, delay); serr != nil {
			return wrapCtx(serr, last)
		}
	}
	return fmt.Errorf("gave up after %d attempts: %w", cfg.MaxAttempts, last)
}

func wrapCtx(ctxErr, last error) error {
	if last == nil {
		return ctxErr
	}
	return fmt.Errorf("%w (last error: %v)", ctxErr, last)
}

// ---------- circuit breaker ----------

var ErrCircuitOpen = errors.New("circuit breaker is open")

type breakerState int

const (
	closed breakerState = iota
	open
	halfOpen
)

// Breaker stops hammering a dependency that is clearly down. After `threshold` consecutive
// retryable failures it opens for `cooldown`, then lets a single trial call through (half-open).
// Permanent errors (client mistakes) do not count as dependency failures.
type Breaker struct {
	mu        sync.Mutex
	threshold int
	cooldown  time.Duration
	now       func() time.Time

	state    breakerState
	failures int
	openedAt time.Time
	trial    bool // a half-open trial call is in flight
}

func NewBreaker(threshold int, cooldown time.Duration) *Breaker {
	if threshold <= 0 {
		threshold = 5
	}
	if cooldown <= 0 {
		cooldown = 30 * time.Second
	}
	return &Breaker{threshold: threshold, cooldown: cooldown, now: time.Now}
}

func (b *Breaker) allow() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch b.state {
	case open:
		if b.now().Sub(b.openedAt) < b.cooldown {
			return Permanent(ErrCircuitOpen) // permanent => the retry loop stops immediately
		}
		b.state, b.trial = halfOpen, true
		return nil
	case halfOpen:
		if b.trial {
			return Permanent(ErrCircuitOpen)
		}
		b.trial = true
	}
	return nil
}

func (b *Breaker) record(err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.trial = false
	if err != nil && !IsPermanent(err) {
		b.failures++
		if b.state == halfOpen || b.failures >= b.threshold {
			b.state, b.openedAt = open, b.now()
		}
		return
	}
	b.state, b.failures = closed, 0
}

// Execute runs fn under breaker protection.
func (b *Breaker) Execute(fn func() error) error {
	if err := b.allow(); err != nil {
		return err
	}
	err := fn()
	b.record(err)
	return err
}

// State returns "closed", "open" or "half-open" (for health endpoints and tests).
func (b *Breaker) State() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return [...]string{"closed", "open", "half-open"}[b.state]
}
