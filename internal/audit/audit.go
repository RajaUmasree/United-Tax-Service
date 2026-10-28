// Package audit implements UTS-GO-107: structured audit logging for order creation, updates,
// document access and integration events.
package audit

import (
	"context"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// Action names are stable identifiers consumed by compliance reporting; do not rename lightly.
const (
	OrderCreated             = "order.created"
	OrderUpdated             = "order.updated"
	OrderValidated           = "order.validated"
	OrderValidationFailed    = "order.validation_failed"
	OrderStatusChanged       = "order.status_changed"
	CertificateRequested     = "certificate.requested"
	CertificateStatusChanged = "certificate.status_changed"
	DocumentUploaded         = "document.uploaded"
	DocumentListed           = "document.listed"
	DocumentAccessed         = "document.accessed"
	AccessDenied             = "access.denied"
	AuthFailed               = "auth.failed"
	IntegrationSucceeded     = "integration.succeeded"
	IntegrationFailed        = "integration.failed"
)

const (
	OutcomeSuccess = "success"
	OutcomeFailure = "failure"
	OutcomeDenied  = "denied"
)

type Event struct {
	Time         time.Time      `json:"time"`
	Action       string         `json:"action"`
	Outcome      string         `json:"outcome"`
	Actor        string         `json:"actor,omitempty"`
	ClientID     string         `json:"client_id,omitempty"`
	RequestID    string         `json:"request_id,omitempty"`
	ResourceType string         `json:"resource_type,omitempty"`
	ResourceID   string         `json:"resource_id,omitempty"`
	Details      map[string]any `json:"details,omitempty"`
}

// Recorder is the sink for audit events. Implementations must be safe for concurrent use and
// must never return an error that would cause a business operation to fail.
type Recorder interface {
	Record(ctx context.Context, e Event)
}

// ---------- context plumbing ----------

type ctxKey int

const (
	keyRequestID ctxKey = iota
	keyActor
	keyClient
)

func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, keyRequestID, id)
}

func RequestID(ctx context.Context) string {
	v, _ := ctx.Value(keyRequestID).(string)
	return v
}

func WithActor(ctx context.Context, actor, clientID string) context.Context {
	ctx = context.WithValue(ctx, keyActor, actor)
	return context.WithValue(ctx, keyClient, clientID)
}

func fill(ctx context.Context, e *Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.RequestID == "" {
		e.RequestID = RequestID(ctx)
	}
	if e.Actor == "" {
		e.Actor, _ = ctx.Value(keyActor).(string)
	}
	if e.ClientID == "" {
		e.ClientID, _ = ctx.Value(keyClient).(string)
	}
	if e.Outcome == "" {
		e.Outcome = OutcomeSuccess
	}
	e.Details = redact(e.Details)
}

var sensitiveKeys = []string{"token", "authorization", "password", "secret", "api_key", "apikey", "content", "ssn"}

// redact guards against accidentally logging credentials or document bytes.
func redact(in map[string]any) map[string]any {
	if len(in) == 0 {
		return in
	}
	out := make(map[string]any, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		redacted := false
		for _, s := range sensitiveKeys {
			if strings.Contains(lk, s) {
				redacted = true
				break
			}
		}
		if redacted {
			out[k] = "[REDACTED]"
		} else {
			out[k] = v
		}
	}
	return out
}

// ---------- slog-backed recorder (production) ----------

type SlogRecorder struct{ Logger *slog.Logger }

func (r SlogRecorder) Record(ctx context.Context, e Event) {
	fill(ctx, &e)
	attrs := []slog.Attr{
		slog.String("log_type", "audit"),
		slog.String("action", e.Action),
		slog.String("outcome", e.Outcome),
		slog.String("actor", e.Actor),
		slog.String("client_id", e.ClientID),
		slog.String("request_id", e.RequestID),
		slog.String("resource_type", e.ResourceType),
		slog.String("resource_id", e.ResourceID),
	}
	if len(e.Details) > 0 {
		attrs = append(attrs, slog.Any("details", e.Details))
	}
	level := slog.LevelInfo
	if e.Outcome != OutcomeSuccess {
		level = slog.LevelWarn
	}
	r.Logger.LogAttrs(ctx, level, "audit", attrs...)
}

// ---------- in-memory recorder (tests) ----------

type MemoryRecorder struct {
	mu     sync.Mutex
	events []Event
}

func (m *MemoryRecorder) Record(ctx context.Context, e Event) {
	fill(ctx, &e)
	m.mu.Lock()
	m.events = append(m.events, e)
	m.mu.Unlock()
}

func (m *MemoryRecorder) Events() []Event {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]Event(nil), m.events...)
}

// Find returns all events with the given action.
func (m *MemoryRecorder) Find(action string) []Event {
	var out []Event
	for _, e := range m.Events() {
		if e.Action == action {
			out = append(out, e)
		}
	}
	return out
}
