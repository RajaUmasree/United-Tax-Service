// Package integration implements UTS-GO-105: Go integration services for external
// title/closing platforms and downstream tax systems. All outbound calls are wrapped with the
// resilience primitives from UTS-GO-106 and every outcome is audited (UTS-GO-107).
package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"uts-tax-service/internal/audit"
	"uts-tax-service/internal/model"
	"uts-tax-service/internal/resilience"
)

// ---------- contracts ----------

// StatusEvent is the payload sent to a title/closing platform when an order changes state.
type StatusEvent struct {
	OrderID      string    `json:"order_id"`
	ExternalRef  string    `json:"external_ref,omitempty"`
	ParcelNumber string    `json:"parcel_number"`
	State        string    `json:"state"`
	County       string    `json:"county"`
	TaxYear      int       `json:"tax_year"`
	Status       string    `json:"status"`
	OccurredAt   time.Time `json:"occurred_at"`
}

// TitlePlatform is an external title/closing system (e.g. a settlement-software vendor).
type TitlePlatform interface {
	PublishStatus(ctx context.Context, ev StatusEvent) error
}

// TaxSystem is the downstream system of record that actually fulfils the tax search.
type TaxSystem interface {
	SubmitOrder(ctx context.Context, o model.Order) (externalRef string, err error)
}

// Integrations is what the API layer depends on.
type Integrations interface {
	NotifyStatus(ctx context.Context, o model.Order) error
	Submit(ctx context.Context, o model.Order) (string, error)
}

// ---------- HTTP client with retries, timeouts and a breaker ----------

type HTTPConfig struct {
	Name    string // used in logs/audit, e.g. "title-platform"
	BaseURL string
	APIKey  string
	Client  *http.Client // optional; defaults to a client with a 15s overall timeout
	Retry   resilience.RetryConfig
	Breaker *resilience.Breaker // optional; a default breaker is created when nil
	Logger  *slog.Logger
}

type httpClient struct {
	cfg HTTPConfig
}

func newHTTPClient(cfg HTTPConfig) *httpClient {
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.Breaker == nil {
		cfg.Breaker = resilience.NewBreaker(5, 30*time.Second)
	}
	if cfg.Retry.PerAttemptTimeout == 0 {
		cfg.Retry.PerAttemptTimeout = 8 * time.Second
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	if cfg.Retry.OnRetry == nil {
		name, lg := cfg.Name, cfg.Logger
		cfg.Retry.OnRetry = func(attempt int, err error, next time.Duration) {
			lg.Warn("integration call failed; will retry", "integration", name, "attempt", attempt, "retry_in", next.String(), "error", err.Error())
		}
	}
	cfg.Retry.Jitter = true
	return &httpClient{cfg: cfg}
}

const maxResponseBytes = 1 << 20

// post sends JSON and decodes the JSON response into out (which may be nil).
// idemKey is sent as Idempotency-Key so a retry after a lost response cannot double-submit.
func (c *httpClient) post(ctx context.Context, path, idemKey string, body, out any) error {
	payload, err := json.Marshal(body)
	if err != nil {
		return resilience.Permanent(fmt.Errorf("marshal request: %w", err))
	}
	url := strings.TrimRight(c.cfg.BaseURL, "/") + path

	return resilience.Do(ctx, c.cfg.Retry, func(actx context.Context) error {
		return c.cfg.Breaker.Execute(func() error {
			req, err := http.NewRequestWithContext(actx, http.MethodPost, url, bytes.NewReader(payload))
			if err != nil {
				return resilience.Permanent(err)
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Accept", "application/json")
			req.Header.Set("Idempotency-Key", idemKey)
			if rid := audit.RequestID(ctx); rid != "" {
				req.Header.Set("X-Request-ID", rid)
			}
			if c.cfg.APIKey != "" {
				req.Header.Set("Authorization", "Bearer "+c.cfg.APIKey)
			}

			resp, err := c.cfg.Client.Do(req)
			if err != nil {
				return fmt.Errorf("%s: request failed: %w", c.cfg.Name, err) // network/timeout => retryable
			}
			defer resp.Body.Close()
			data, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))

			switch {
			case resp.StatusCode >= 200 && resp.StatusCode < 300:
				if out != nil && len(data) > 0 {
					if err := json.Unmarshal(data, out); err != nil {
						return resilience.Permanent(fmt.Errorf("%s: decode response: %w", c.cfg.Name, err))
					}
				}
				return nil
			case resp.StatusCode == http.StatusRequestTimeout, resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode >= 500:
				return fmt.Errorf("%s: transient status %d", c.cfg.Name, resp.StatusCode)
			default: // other 4xx: our request is wrong; retrying cannot help
				return resilience.Permanent(fmt.Errorf("%s: status %d: %s", c.cfg.Name, resp.StatusCode, snippet(data)))
			}
		})
	})
}

func snippet(b []byte) string {
	s := strings.TrimSpace(string(b))
	if len(s) > 200 {
		s = s[:200] + "..."
	}
	return s
}

// ---------- title / closing platform ----------

type TitlePlatformClient struct{ c *httpClient }

func NewTitlePlatformClient(cfg HTTPConfig) *TitlePlatformClient {
	if cfg.Name == "" {
		cfg.Name = "title-platform"
	}
	return &TitlePlatformClient{c: newHTTPClient(cfg)}
}

func (t *TitlePlatformClient) PublishStatus(ctx context.Context, ev StatusEvent) error {
	key := fmt.Sprintf("%s:%s", ev.OrderID, ev.Status) // one logical event per (order,status)
	return t.c.post(ctx, "/v1/tax-orders/status", key, ev, nil)
}

// ---------- downstream tax system ----------

type TaxSystemClient struct{ c *httpClient }

func NewTaxSystemClient(cfg HTTPConfig) *TaxSystemClient {
	if cfg.Name == "" {
		cfg.Name = "tax-system"
	}
	return &TaxSystemClient{c: newHTTPClient(cfg)}
}

type taxSubmitRequest struct {
	OrderID         string `json:"order_id"`
	ParcelNumber    string `json:"parcel_number"`
	PropertyAddress string `json:"property_address"`
	State           string `json:"state"`
	County          string `json:"county"`
	Jurisdiction    string `json:"jurisdiction"`
	TaxYear         int    `json:"tax_year"`
	OwnerName       string `json:"owner_name"`
}

type taxSubmitResponse struct {
	Reference string `json:"reference"`
}

func (t *TaxSystemClient) SubmitOrder(ctx context.Context, o model.Order) (string, error) {
	var resp taxSubmitResponse
	err := t.c.post(ctx, "/v1/tax-searches", fmt.Sprintf("submit:%s:v%d", o.ID, o.Version), taxSubmitRequest{
		OrderID: o.ID, ParcelNumber: o.ParcelNumber, PropertyAddress: o.PropertyAddress,
		State: o.State, County: o.County, Jurisdiction: o.Jurisdiction, TaxYear: o.TaxYear, OwnerName: o.OwnerName,
	}, &resp)
	if err != nil {
		return "", err
	}
	if resp.Reference == "" {
		return "", resilience.Permanent(fmt.Errorf("%s: response missing reference", "tax-system"))
	}
	return resp.Reference, nil
}

// ---------- dispatcher (audited facade used by the API) ----------

type Dispatcher struct {
	Title TitlePlatform // may be nil
	Tax   TaxSystem     // may be nil
	Audit audit.Recorder
}

func (d *Dispatcher) NotifyStatus(ctx context.Context, o model.Order) error {
	if d.Title == nil {
		return nil
	}
	err := d.Title.PublishStatus(ctx, StatusEvent{
		OrderID: o.ID, ExternalRef: o.ExternalRef, ParcelNumber: o.ParcelNumber, State: o.State,
		County: o.County, TaxYear: o.TaxYear, Status: string(o.Status), OccurredAt: time.Now().UTC(),
	})
	d.record(ctx, "title-platform", "publish_status", o.ID, err, map[string]any{"status": string(o.Status)})
	return err
}

func (d *Dispatcher) Submit(ctx context.Context, o model.Order) (string, error) {
	if d.Tax == nil {
		return "", nil
	}
	ref, err := d.Tax.SubmitOrder(ctx, o)
	details := map[string]any{}
	if err == nil {
		details["external_ref"] = ref
	}
	d.record(ctx, "tax-system", "submit_order", o.ID, err, details)
	return ref, err
}

func (d *Dispatcher) record(ctx context.Context, system, op, orderID string, err error, details map[string]any) {
	if d.Audit == nil {
		return
	}
	if details == nil {
		details = map[string]any{}
	}
	details["system"], details["operation"] = system, op
	ev := audit.Event{Action: audit.IntegrationSucceeded, Outcome: audit.OutcomeSuccess, ResourceType: "order", ResourceID: orderID, Details: details}
	if err != nil {
		ev.Action, ev.Outcome = audit.IntegrationFailed, audit.OutcomeFailure
		details["error"] = err.Error()
		details["circuit_open"] = errorsIsCircuitOpen(err)
	}
	d.Audit.Record(ctx, ev)
}

func errorsIsCircuitOpen(err error) bool {
	return err != nil && strings.Contains(err.Error(), resilience.ErrCircuitOpen.Error())
}

// Noop is used when no external systems are configured (local development).
type Noop struct{}

func (Noop) NotifyStatus(context.Context, model.Order) error     { return nil }
func (Noop) Submit(context.Context, model.Order) (string, error) { return "", nil }
