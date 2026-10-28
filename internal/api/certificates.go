package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"uts-tax-service/internal/audit"
	"uts-tax-service/internal/model"
	"uts-tax-service/internal/validation"
)

// UTS-GO-102: tax certificate requests managed through defined processing states.

type createCertificateRequest struct {
	Type  string `json:"type"`
	Notes string `json:"notes,omitempty"`
}

type certStatusRequest struct {
	Status string `json:"status"`
	Notes  string `json:"notes,omitempty"`
}

func applyCertTransition(c *model.Certificate, to model.CertificateStatus, by, notes string, now time.Time) error {
	if !c.Status.CanTransitionTo(to) {
		return fmt.Errorf("%w: %s -> %s", errBadTransition, c.Status, to)
	}
	c.StatusHistory = append(c.StatusHistory, model.StatusChange{From: string(c.Status), To: string(to), At: now, By: by, Reason: notes})
	c.Status = to
	if notes != "" {
		c.Notes = notes
	}
	return nil
}

func (s *Server) createCertificate(w http.ResponseWriter, r *http.Request) {
	o, p, ok := s.loadOrder(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var req createCertificateRequest
	if !s.decode(w, r, s.cfg.MaxBodyBytes, &req) {
		return
	}
	req.Type = strings.ToUpper(strings.TrimSpace(req.Type))
	req.Notes = strings.TrimSpace(req.Notes)
	errs := validation.ValidateCertificateType(req.Type)
	if len(req.Notes) > 1000 {
		errs = append(errs, validation.FieldError{Field: "notes", Code: "invalid_length", Message: "notes must be 1000 characters or fewer"})
	}
	if len(errs) > 0 {
		writeValidation(w, r, errs)
		return
	}
	if o.Status != model.OrderValidated && o.Status != model.OrderInProgress {
		writeError(w, r, http.StatusConflict, "order_not_ready", "certificates can only be requested for VALIDATED or IN_PROGRESS orders", nil)
		return
	}
	for _, ex := range s.store.ListCertificates(o.ID) {
		if ex.Type == req.Type && (ex.Status == model.CertRequested || ex.Status == model.CertInReview) {
			writeError(w, r, http.StatusConflict, "duplicate_certificate", "an open certificate request of this type already exists for the order", map[string]string{"certificate_id": ex.ID})
			return
		}
	}

	now := s.now()
	c, err := s.store.CreateCertificate(model.Certificate{
		ID: model.NewID("crt"), OrderID: o.ID, Type: req.Type, Status: model.CertRequested, Notes: req.Notes,
		RequestedBy: p.Actor, Version: 1, CreatedAt: now, UpdatedAt: now,
		StatusHistory: []model.StatusChange{{To: string(model.CertRequested), At: now, By: p.Actor}},
	})
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not create certificate request", nil)
		return
	}
	s.record(r.Context(), audit.CertificateRequested, "certificate", c.ID, audit.OutcomeSuccess, map[string]any{"order_id": o.ID, "type": c.Type})
	w.Header().Set("Location", "/v1/certificates/"+c.ID)
	writeJSON(w, http.StatusCreated, c)
}

func (s *Server) listCertificates(w http.ResponseWriter, r *http.Request) {
	o, _, ok := s.loadOrder(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	certs := s.store.ListCertificates(o.ID)
	if certs == nil {
		certs = []model.Certificate{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"certificates": certs, "count": len(certs)})
}

// loadCertificate resolves the certificate and applies the owning order's tenant check.
func (s *Server) loadCertificate(w http.ResponseWriter, r *http.Request) (model.Certificate, model.Order, Principal, bool) {
	c, err := s.store.GetCertificate(r.PathValue("id"))
	if err != nil {
		writeError(w, r, http.StatusNotFound, "not_found", "certificate not found", nil)
		return model.Certificate{}, model.Order{}, Principal{}, false
	}
	o, p, ok := s.loadOrder(w, r, c.OrderID)
	return c, o, p, ok
}

func (s *Server) getCertificate(w http.ResponseWriter, r *http.Request) {
	c, _, _, ok := s.loadCertificate(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, c)
}

func (s *Server) changeCertificateStatus(w http.ResponseWriter, r *http.Request) {
	c, o, p, ok := s.loadCertificate(w, r)
	if !ok {
		return
	}
	var req certStatusRequest
	if !s.decode(w, r, s.cfg.MaxBodyBytes, &req) {
		return
	}
	to := model.CertificateStatus(strings.ToUpper(strings.TrimSpace(req.Status)))
	if !to.Valid() {
		writeValidation(w, r, validation.Errors{{Field: "status", Code: "invalid_value", Message: "unknown certificate status"}})
		return
	}
	if !p.Staff() && to != model.CertCancelled {
		s.record(r.Context(), audit.AccessDenied, "certificate", c.ID, audit.OutcomeDenied, map[string]any{"reason": "clients may only cancel", "requested_status": string(to)})
		writeError(w, r, http.StatusForbidden, "forbidden", "clients may only cancel their own certificate requests", nil)
		return
	}
	notes := strings.TrimSpace(req.Notes)
	if len(notes) > 1000 {
		writeValidation(w, r, validation.Errors{{Field: "notes", Code: "invalid_length", Message: "notes must be 1000 characters or fewer"}})
		return
	}
	var from model.CertificateStatus
	updated, err := s.store.UpdateCertificate(c.ID, func(cur *model.Certificate) error {
		from = cur.Status
		return applyCertTransition(cur, to, p.Actor, notes, s.now())
	})
	if errors.Is(err, errBadTransition) {
		s.record(r.Context(), audit.CertificateStatusChanged, "certificate", c.ID, audit.OutcomeFailure, map[string]any{"from": string(c.Status), "to": string(to), "order_id": o.ID})
		writeError(w, r, http.StatusConflict, "invalid_transition", err.Error(), nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not change certificate status", nil)
		return
	}
	s.record(r.Context(), audit.CertificateStatusChanged, "certificate", c.ID, audit.OutcomeSuccess, map[string]any{"from": string(from), "to": string(to), "order_id": o.ID})
	writeJSON(w, http.StatusOK, updated)
}
