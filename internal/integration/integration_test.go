package integration

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"uts-tax-service/internal/audit"
	"uts-tax-service/internal/model"
	"uts-tax-service/internal/resilience"
)

func fastRetry(attempts int) resilience.RetryConfig {
	return resilience.RetryConfig{
		MaxAttempts: attempts, BaseDelay: time.Millisecond, MaxDelay: 2 * time.Millisecond,
		PerAttemptTimeout: 500 * time.Millisecond,
	}
}

func order() model.Order {
	return model.Order{ID: "ord_1", ParcelNumber: "R-1", PropertyAddress: "1 Main St", State: "AR", County: "Benton",
		Jurisdiction: "Benton County", TaxYear: 2025, OwnerName: "Jane", Version: 3, Status: model.OrderInProgress}
}

func TestTaxSystem_RetriesTransientThenSucceeds(t *testing.T) {
	var hits atomic.Int32
	var gotKey, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey, gotAuth = r.Header.Get("Idempotency-Key"), r.Header.Get("Authorization")
		if hits.Add(1) < 3 {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"reference": "TX-998"})
	}))
	defer srv.Close()

	c := NewTaxSystemClient(HTTPConfig{BaseURL: srv.URL, APIKey: "k", Retry: fastRetry(4)})
	ref, err := c.SubmitOrder(context.Background(), order())
	if err != nil || ref != "TX-998" || hits.Load() != 3 {
		t.Fatalf("ref=%q err=%v hits=%d", ref, err, hits.Load())
	}
	if gotKey != "submit:ord_1:v3" || gotAuth != "Bearer k" {
		t.Fatalf("headers: key=%q auth=%q", gotKey, gotAuth)
	}
}

func TestTaxSystem_4xxIsNotRetried(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "unknown parcel", http.StatusUnprocessableEntity)
	}))
	defer srv.Close()
	c := NewTaxSystemClient(HTTPConfig{BaseURL: srv.URL, Retry: fastRetry(5)})
	_, err := c.SubmitOrder(context.Background(), order())
	if err == nil || hits.Load() != 1 || !resilience.IsPermanent(err) {
		t.Fatalf("err=%v hits=%d", err, hits.Load())
	}
}

func TestTaxSystem_MissingReferenceIsError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{}`)) }))
	defer srv.Close()
	c := NewTaxSystemClient(HTTPConfig{BaseURL: srv.URL, Retry: fastRetry(2)})
	if _, err := c.SubmitOrder(context.Background(), order()); err == nil {
		t.Fatal("expected error for response without reference")
	}
}

func TestClient_TimeoutTriggersRetry(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			time.Sleep(300 * time.Millisecond) // exceeds per-attempt timeout
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"reference": "OK"})
	}))
	defer srv.Close()
	cfg := fastRetry(3)
	cfg.PerAttemptTimeout = 80 * time.Millisecond
	c := NewTaxSystemClient(HTTPConfig{BaseURL: srv.URL, Retry: cfg})
	ref, err := c.SubmitOrder(context.Background(), order())
	if err != nil || ref != "OK" || hits.Load() < 2 {
		t.Fatalf("ref=%q err=%v hits=%d", ref, err, hits.Load())
	}
}

func TestClient_CircuitOpensAndFailsFast(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := NewTaxSystemClient(HTTPConfig{BaseURL: srv.URL, Retry: fastRetry(1), Breaker: resilience.NewBreaker(2, time.Minute)})
	for i := 0; i < 2; i++ {
		_, _ = c.SubmitOrder(context.Background(), order())
	}
	before := hits.Load()
	_, err := c.SubmitOrder(context.Background(), order())
	if !errors.Is(err, resilience.ErrCircuitOpen) || hits.Load() != before {
		t.Fatalf("expected fail-fast with no network call: err=%v hits=%d->%d", err, before, hits.Load())
	}
}

func TestTitlePlatform_PublishStatusPayload(t *testing.T) {
	var ev StatusEvent
	var key string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key = r.Header.Get("Idempotency-Key")
		_ = json.NewDecoder(r.Body).Decode(&ev)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	c := NewTitlePlatformClient(HTTPConfig{BaseURL: srv.URL, Retry: fastRetry(2)})
	err := c.PublishStatus(context.Background(), StatusEvent{OrderID: "ord_1", Status: "COMPLETED", ParcelNumber: "R-1"})
	if err != nil || ev.OrderID != "ord_1" || ev.Status != "COMPLETED" || key != "ord_1:COMPLETED" {
		t.Fatalf("err=%v ev=%+v key=%q", err, ev, key)
	}
}

type failingTax struct{}

func (failingTax) SubmitOrder(context.Context, model.Order) (string, error) {
	return "", errors.New("tax system unavailable")
}

type okTitle struct{ got []StatusEvent }

func (o *okTitle) PublishStatus(_ context.Context, ev StatusEvent) error {
	o.got = append(o.got, ev)
	return nil
}

func TestDispatcher_AuditsSuccessAndFailure(t *testing.T) {
	rec := &audit.MemoryRecorder{}
	title := &okTitle{}
	d := &Dispatcher{Title: title, Tax: failingTax{}, Audit: rec}

	if err := d.NotifyStatus(context.Background(), order()); err != nil || len(title.got) != 1 {
		t.Fatalf("notify err=%v events=%d", err, len(title.got))
	}
	if _, err := d.Submit(context.Background(), order()); err == nil {
		t.Fatal("expected submit error")
	}
	if len(rec.Find(audit.IntegrationSucceeded)) != 1 {
		t.Fatalf("want 1 success event, got %+v", rec.Events())
	}
	fails := rec.Find(audit.IntegrationFailed)
	if len(fails) != 1 || fails[0].Outcome != audit.OutcomeFailure || fails[0].Details["system"] != "tax-system" {
		t.Fatalf("bad failure event: %+v", fails)
	}
}

func TestDispatcher_NilSystemsAreNoops(t *testing.T) {
	d := &Dispatcher{}
	if err := d.NotifyStatus(context.Background(), order()); err != nil {
		t.Fatal(err)
	}
	if ref, err := d.Submit(context.Background(), order()); err != nil || ref != "" {
		t.Fatalf("ref=%q err=%v", ref, err)
	}
}
