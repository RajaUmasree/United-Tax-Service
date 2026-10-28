// Package api exposes the HTTP surface for UTS-GO-101..103 and wires auth, audit and integrations.
package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"uts-tax-service/internal/audit"
	"uts-tax-service/internal/integration"
	"uts-tax-service/internal/model"
	"uts-tax-service/internal/store"
	"uts-tax-service/internal/validation"
)

type Config struct {
	MaxBodyBytes      int64         // default 1 MiB for JSON endpoints
	MaxDocBytes       int           // default 10 MiB per document
	BackgroundTimeout time.Duration // budget for async integration work, default 2 minutes
}

type Server struct {
	store store.Store
	integ integration.Integrations
	audit audit.Recorder
	auth  Authenticator
	log   *slog.Logger
	cfg   Config
	now   func() time.Time
	wg    sync.WaitGroup
}

func New(st store.Store, integ integration.Integrations, rec audit.Recorder, auth Authenticator, log *slog.Logger, cfg Config) *Server {
	if cfg.MaxBodyBytes <= 0 {
		cfg.MaxBodyBytes = 1 << 20
	}
	if cfg.MaxDocBytes <= 0 {
		cfg.MaxDocBytes = 10 << 20
	}
	if cfg.BackgroundTimeout <= 0 {
		cfg.BackgroundTimeout = 2 * time.Minute
	}
	if integ == nil {
		integ = integration.Noop{}
	}
	if log == nil {
		log = slog.Default()
	}
	return &Server{store: st, integ: integ, audit: rec, auth: auth, log: log, cfg: cfg, now: func() time.Time { return time.Now().UTC() }}
}

// Wait blocks until in-flight background integration work finishes (graceful shutdown, tests).
func (s *Server) Wait() { s.wg.Wait() }

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})

	// UTS-GO-101: orders
	mux.HandleFunc("POST /v1/orders", s.createOrder)
	mux.HandleFunc("GET /v1/orders", s.listOrders)
	mux.HandleFunc("GET /v1/orders/{id}", s.getOrder)
	mux.HandleFunc("PUT /v1/orders/{id}", s.updateOrder)
	mux.HandleFunc("POST /v1/orders/{id}/validate", s.validateOrder)
	mux.HandleFunc("PATCH /v1/orders/{id}/status", s.changeOrderStatus)
	mux.HandleFunc("GET /v1/orders/{id}/status", s.getOrderStatus)

	// UTS-GO-102: certificates
	mux.HandleFunc("POST /v1/orders/{id}/certificates", s.createCertificate)
	mux.HandleFunc("GET /v1/orders/{id}/certificates", s.listCertificates)
	mux.HandleFunc("GET /v1/certificates/{id}", s.getCertificate)
	mux.HandleFunc("PATCH /v1/certificates/{id}/status", s.changeCertificateStatus)

	// UTS-GO-103: documents
	mux.HandleFunc("POST /v1/orders/{id}/documents", s.uploadDocument)
	mux.HandleFunc("GET /v1/orders/{id}/documents", s.listDocuments)
	mux.HandleFunc("GET /v1/orders/{id}/documents/{docID}", s.downloadDocument)

	var h http.Handler = mux
	h = s.authMiddleware(h)
	h = securityHeaders(h)
	h = s.recoverMiddleware(h)
	h = s.accessLog(h)
	h = requestID(h)
	return h
}

// ---------- middleware ----------

type ctxKey struct{}

func principalFrom(ctx context.Context) Principal {
	p, _ := ctx.Value(ctxKey{}).(Principal)
	return p
}

var safeReqID = regexp.MustCompile(`^[A-Za-z0-9._\-]{8,64}$`)

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if !safeReqID.MatchString(id) {
			b := make([]byte, 8)
			_, _ = rand.Read(b)
			id = "req-" + hex.EncodeToString(b)
		}
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(audit.WithRequestID(r.Context(), id)))
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (sr *statusRecorder) WriteHeader(code int) {
	sr.status = code
	sr.ResponseWriter.WriteHeader(code)
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sr := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sr, r)
		s.log.Info("http request", "method", r.Method, "path", r.URL.Path, "status", sr.status,
			"duration_ms", time.Since(start).Milliseconds(), "request_id", audit.RequestID(r.Context()))
	})
}

func (s *Server) recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic in handler", "panic", fmt.Sprint(rec), "request_id", audit.RequestID(r.Context()))
				writeError(w, r, http.StatusInternalServerError, "internal_error", "internal server error", nil)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Cache-Control", "no-store")
		h.Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) authMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			next.ServeHTTP(w, r)
			return
		}
		authz := r.Header.Get("Authorization")
		token, hasBearer := strings.CutPrefix(authz, "Bearer ")
		var (
			p  Principal
			ok bool
		)
		if hasBearer && token != "" {
			p, ok = s.auth.Authenticate(token)
		}
		if !ok {
			s.record(r.Context(), audit.AuthFailed, "", "", audit.OutcomeDenied, map[string]any{
				"path": r.URL.Path, "method": r.Method, "remote_addr": r.RemoteAddr, "bearer_present": hasBearer,
			})
			w.Header().Set("WWW-Authenticate", `Bearer realm="uts-tax"`)
			writeError(w, r, http.StatusUnauthorized, "unauthorized", "missing or invalid credentials", nil)
			return
		}
		ctx := context.WithValue(r.Context(), ctxKey{}, p)
		ctx = audit.WithActor(ctx, p.Actor, p.ClientID)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// ---------- helpers ----------

func (s *Server) record(ctx context.Context, action, resType, resID, outcome string, details map[string]any) {
	if s.audit == nil {
		return
	}
	s.audit.Record(ctx, audit.Event{Action: action, ResourceType: resType, ResourceID: resID, Outcome: outcome, Details: details})
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

type errorBody struct {
	Error struct {
		Code      string `json:"code"`
		Message   string `json:"message"`
		RequestID string `json:"request_id,omitempty"`
		Details   any    `json:"details,omitempty"`
	} `json:"error"`
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, msg string, details any) {
	var b errorBody
	b.Error.Code, b.Error.Message, b.Error.Details = code, msg, details
	b.Error.RequestID = audit.RequestID(r.Context())
	writeJSON(w, status, b)
}

func writeValidation(w http.ResponseWriter, r *http.Request, errs validation.Errors) {
	writeError(w, r, http.StatusUnprocessableEntity, "validation_failed", "request failed validation", errs)
}

// decode reads a single JSON object, rejecting unknown fields, trailing data and oversized bodies.
func (s *Server) decode(w http.ResponseWriter, r *http.Request, limit int64, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, limit)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			writeError(w, r, http.StatusRequestEntityTooLarge, "body_too_large", "request body too large", nil)
		} else {
			writeError(w, r, http.StatusBadRequest, "invalid_json", "request body is not valid JSON for this endpoint: "+err.Error(), nil)
		}
		return false
	}
	if dec.More() {
		writeError(w, r, http.StatusBadRequest, "invalid_json", "request body must contain a single JSON object", nil)
		return false
	}
	return true
}

// background runs integration work off the request path, detached from request cancellation
// but still carrying request-id/actor values for audit correlation.
func (s *Server) background(parent context.Context, fn func(ctx context.Context)) {
	ctx, cancel := context.WithTimeout(context.WithoutCancel(parent), s.cfg.BackgroundTimeout)
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer cancel()
		defer func() {
			if rec := recover(); rec != nil {
				s.log.Error("panic in background task", "panic", fmt.Sprint(rec))
			}
		}()
		fn(ctx)
	}()
}

// loadOrder fetches an order and enforces tenant isolation. A caller who may not see the order
// gets 404 (not 403) so order IDs cannot be probed; the attempt is audited.
func (s *Server) loadOrder(w http.ResponseWriter, r *http.Request, id string) (model.Order, Principal, bool) {
	p := principalFrom(r.Context())
	o, err := s.store.GetOrder(id)
	if err != nil || !p.CanAccessClient(o.ClientID) {
		if err == nil {
			s.record(r.Context(), audit.AccessDenied, "order", id, audit.OutcomeDenied, map[string]any{"method": r.Method, "path": r.URL.Path})
		}
		writeError(w, r, http.StatusNotFound, "not_found", "order not found", nil)
		return model.Order{}, p, false
	}
	return o, p, true
}

func (s *Server) requireStaff(w http.ResponseWriter, r *http.Request, p Principal, resType, resID string) bool {
	if p.Staff() {
		return true
	}
	s.record(r.Context(), audit.AccessDenied, resType, resID, audit.OutcomeDenied, map[string]any{"reason": "staff role required", "path": r.URL.Path})
	writeError(w, r, http.StatusForbidden, "forbidden", "this operation requires a staff role", nil)
	return false
}

var (
	errVersionConflict = errors.New("version conflict")
	errNotEditable     = errors.New("resource is not editable in its current status")
	errNoChange        = errors.New("no change")
	errBadTransition   = errors.New("invalid status transition")
)

func applyOrderTransition(o *model.Order, to model.OrderStatus, by, reason string, now time.Time) error {
	if !o.Status.CanTransitionTo(to) {
		return fmt.Errorf("%w: %s -> %s", errBadTransition, o.Status, to)
	}
	o.StatusHistory = append(o.StatusHistory, model.StatusChange{From: string(o.Status), To: string(to), At: now, By: by, Reason: reason})
	o.Status = to
	return nil
}
