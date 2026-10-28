package audit

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"
)

func TestMemoryRecorder_FillsContextAndDefaults(t *testing.T) {
	ctx := WithActor(WithRequestID(context.Background(), "req-12345678"), "alice", "acme")
	rec := &MemoryRecorder{}
	rec.Record(ctx, Event{Action: OrderCreated, ResourceType: "order", ResourceID: "ord_1"})
	ev := rec.Events()[0]
	if ev.Actor != "alice" || ev.ClientID != "acme" || ev.RequestID != "req-12345678" || ev.Outcome != OutcomeSuccess || ev.Time.IsZero() {
		t.Fatalf("event not enriched: %+v", ev)
	}
}

func TestRedactsSensitiveDetails(t *testing.T) {
	rec := &MemoryRecorder{}
	rec.Record(context.Background(), Event{Action: DocumentAccessed, Details: map[string]any{
		"authorization": "Bearer abc", "api_key": "k", "content": "bytes", "name": "tax.pdf",
	}})
	d := rec.Events()[0].Details
	if d["authorization"] != "[REDACTED]" || d["api_key"] != "[REDACTED]" || d["content"] != "[REDACTED]" || d["name"] != "tax.pdf" {
		t.Fatalf("unexpected redaction: %v", d)
	}
}

func TestSlogRecorder_EmitsStructuredJSON(t *testing.T) {
	var buf bytes.Buffer
	r := SlogRecorder{Logger: slog.New(slog.NewJSONHandler(&buf, nil))}
	ctx := WithActor(WithRequestID(context.Background(), "req-abcdefgh"), "bob", "c1")
	r.Record(ctx, Event{Action: AccessDenied, Outcome: OutcomeDenied, ResourceType: "order", ResourceID: "ord_9"})

	var line map[string]any
	if err := json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &line); err != nil {
		t.Fatalf("not JSON: %v: %s", err, buf.String())
	}
	if line["log_type"] != "audit" || line["action"] != AccessDenied || line["actor"] != "bob" ||
		line["request_id"] != "req-abcdefgh" || line["level"] != "WARN" {
		t.Fatalf("unexpected audit line: %v", line)
	}
}
