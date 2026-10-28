package resilience

import (
	"context"
	"errors"
	"testing"
	"time"
)

func noSleep(slept *[]time.Duration) func(context.Context, time.Duration) error {
	return func(ctx context.Context, d time.Duration) error {
		*slept = append(*slept, d)
		return ctx.Err()
	}
}

func TestDo_SucceedsAfterTransientFailures(t *testing.T) {
	var slept []time.Duration
	calls := 0
	err := Do(context.Background(), RetryConfig{MaxAttempts: 4, BaseDelay: 100 * time.Millisecond, MaxDelay: time.Second, Sleep: noSleep(&slept)},
		func(context.Context) error {
			calls++
			if calls < 3 {
				return errors.New("boom")
			}
			return nil
		})
	if err != nil || calls != 3 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	if len(slept) != 2 || slept[0] != 100*time.Millisecond || slept[1] != 200*time.Millisecond {
		t.Fatalf("unexpected exponential backoff: %v", slept)
	}
}

func TestDo_BackoffIsCapped(t *testing.T) {
	var slept []time.Duration
	_ = Do(context.Background(), RetryConfig{MaxAttempts: 5, BaseDelay: time.Second, MaxDelay: 3 * time.Second, Sleep: noSleep(&slept)},
		func(context.Context) error { return errors.New("x") })
	for _, d := range slept {
		if d > 3*time.Second {
			t.Fatalf("delay %v exceeds cap", d)
		}
	}
}

func TestDo_JitterStaysWithinBounds(t *testing.T) {
	cfg := RetryConfig{BaseDelay: time.Second, MaxDelay: 10 * time.Second, Jitter: true}.withDefaults()
	for i := 0; i < 200; i++ {
		d := cfg.backoff(2) // nominal 2s
		if d < time.Second || d > 2*time.Second {
			t.Fatalf("jittered delay %v outside [1s,2s]", d)
		}
	}
}

func TestDo_PermanentErrorStopsImmediately(t *testing.T) {
	calls := 0
	sentinel := errors.New("bad request")
	err := Do(context.Background(), RetryConfig{MaxAttempts: 5, Sleep: func(context.Context, time.Duration) error { return nil }},
		func(context.Context) error { calls++; return Permanent(sentinel) })
	if calls != 1 || !errors.Is(err, sentinel) || !IsPermanent(err) {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestDo_ExhaustsAttempts(t *testing.T) {
	calls := 0
	sentinel := errors.New("down")
	err := Do(context.Background(), RetryConfig{MaxAttempts: 3, Sleep: func(context.Context, time.Duration) error { return nil }},
		func(context.Context) error { calls++; return sentinel })
	if calls != 3 || !errors.Is(err, sentinel) {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}

func TestDo_PerAttemptTimeout(t *testing.T) {
	calls := 0
	start := time.Now()
	err := Do(context.Background(), RetryConfig{MaxAttempts: 2, PerAttemptTimeout: 30 * time.Millisecond, Sleep: func(context.Context, time.Duration) error { return nil }},
		func(ctx context.Context) error {
			calls++
			<-ctx.Done() // simulates a hung dependency
			return ctx.Err()
		})
	if !errors.Is(err, context.DeadlineExceeded) || calls != 2 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
	if time.Since(start) > time.Second {
		t.Fatal("per-attempt timeout did not bound the call")
	}
}

func TestDo_ParentContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	calls := 0
	err := Do(ctx, RetryConfig{MaxAttempts: 5, BaseDelay: time.Hour}, func(context.Context) error {
		calls++
		cancel() // cancel while waiting for backoff
		return errors.New("fail")
	})
	if !errors.Is(err, context.Canceled) || calls != 1 {
		t.Fatalf("err=%v calls=%d", err, calls)
	}
}

func TestDo_OnRetryCalled(t *testing.T) {
	n := 0
	_ = Do(context.Background(), RetryConfig{MaxAttempts: 3, Sleep: func(context.Context, time.Duration) error { return nil },
		OnRetry: func(int, error, time.Duration) { n++ }}, func(context.Context) error { return errors.New("x") })
	if n != 2 {
		t.Fatalf("OnRetry called %d times, want 2", n)
	}
}

func TestBreaker_OpensAfterThresholdAndRecovers(t *testing.T) {
	now := time.Unix(1000, 0)
	b := NewBreaker(3, 10*time.Second)
	b.now = func() time.Time { return now }
	fail := func() error { return errors.New("down") }

	for i := 0; i < 3; i++ {
		_ = b.Execute(fail)
	}
	if b.State() != "open" {
		t.Fatalf("state=%s, want open", b.State())
	}
	called := false
	err := b.Execute(func() error { called = true; return nil })
	if !errors.Is(err, ErrCircuitOpen) || !IsPermanent(err) || called {
		t.Fatalf("open breaker must reject without calling: err=%v called=%v", err, called)
	}

	now = now.Add(11 * time.Second) // cooldown elapsed -> half-open trial
	if err := b.Execute(func() error { return nil }); err != nil {
		t.Fatalf("trial call failed: %v", err)
	}
	if b.State() != "closed" {
		t.Fatalf("state=%s, want closed after successful trial", b.State())
	}
}

func TestBreaker_FailedTrialReopens(t *testing.T) {
	now := time.Unix(1000, 0)
	b := NewBreaker(1, 5*time.Second)
	b.now = func() time.Time { return now }
	_ = b.Execute(func() error { return errors.New("down") })
	now = now.Add(6 * time.Second)
	_ = b.Execute(func() error { return errors.New("still down") })
	if b.State() != "open" {
		t.Fatalf("state=%s, want open after failed trial", b.State())
	}
}

func TestBreaker_PermanentErrorsDoNotTrip(t *testing.T) {
	b := NewBreaker(2, time.Minute)
	for i := 0; i < 10; i++ {
		_ = b.Execute(func() error { return Permanent(errors.New("400")) })
	}
	if b.State() != "closed" {
		t.Fatalf("state=%s; client errors must not open the breaker", b.State())
	}
}

func TestDoWithBreaker_StopsRetryingWhenOpen(t *testing.T) {
	b := NewBreaker(1, time.Minute)
	calls := 0
	cfg := RetryConfig{MaxAttempts: 5, Sleep: func(context.Context, time.Duration) error { return nil }}
	err := Do(context.Background(), cfg, func(context.Context) error {
		return b.Execute(func() error { calls++; return errors.New("down") })
	})
	if calls != 1 || !errors.Is(err, ErrCircuitOpen) {
		t.Fatalf("calls=%d err=%v", calls, err)
	}
}
