package api

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"

	"uts-tax-service/internal/audit"
	"uts-tax-service/internal/model"
	"uts-tax-service/internal/store"
	"uts-tax-service/internal/validation"
)

// UTS-GO-101: property-tax order creation, validation, updates and status tracking.

type createOrderRequest struct {
	validation.OrderInput
	ClientID string `json:"client_id,omitempty"` // honoured for staff only
}

type updateOrderRequest struct {
	validation.OrderInput
	Version int `json:"version"` // must match the current version (optimistic concurrency)
}

type statusRequest struct {
	Status string `json:"status"`
	Reason string `json:"reason,omitempty"`
}

func inputOf(o model.Order) validation.OrderInput {
	return validation.OrderInput{
		ParcelNumber: o.ParcelNumber, PropertyAddress: o.PropertyAddress, State: o.State,
		County: o.County, Jurisdiction: o.Jurisdiction, TaxYear: o.TaxYear, OwnerName: o.OwnerName,
	}
}

func changedFields(o model.Order, in validation.OrderInput) []string {
	var f []string
	add := func(name string, differs bool) {
		if differs {
			f = append(f, name)
		}
	}
	add("parcel_number", o.ParcelNumber != in.ParcelNumber)
	add("property_address", o.PropertyAddress != in.PropertyAddress)
	add("state", o.State != in.State)
	add("county", o.County != in.County)
	add("jurisdiction", o.Jurisdiction != in.Jurisdiction)
	add("tax_year", o.TaxYear != in.TaxYear)
	add("owner_name", o.OwnerName != in.OwnerName)
	return f
}

func (s *Server) createOrder(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	var req createOrderRequest
	if !s.decode(w, r, s.cfg.MaxBodyBytes, &req) {
		return
	}
	in := validation.Normalize(req.OrderInput)
	now := s.now()
	if errs := validation.ValidateOrderInput(in, now); len(errs) > 0 {
		s.record(r.Context(), audit.OrderValidationFailed, "order", "", audit.OutcomeFailure, map[string]any{"stage": "create", "error_count": len(errs)})
		writeValidation(w, r, errs)
		return
	}

	clientID := p.ClientID
	if p.Staff() {
		clientID = strings.TrimSpace(req.ClientID)
	}
	if clientID == "" {
		writeValidation(w, r, validation.Errors{{Field: "client_id", Code: "required", Message: "client_id is required when creating an order as staff"}})
		return
	}

	o := model.Order{
		ID: model.NewID("ord"), ClientID: clientID,
		ParcelNumber: in.ParcelNumber, PropertyAddress: in.PropertyAddress, State: in.State, County: in.County,
		Jurisdiction: in.Jurisdiction, TaxYear: in.TaxYear, OwnerName: in.OwnerName,
		Status: model.OrderCreated, Version: 1, CreatedBy: p.Actor, CreatedAt: now, UpdatedAt: now,
		StatusHistory: []model.StatusChange{{To: string(model.OrderCreated), At: now, By: p.Actor}},
	}
	created, err := s.store.CreateOrder(o)
	if errors.Is(err, store.ErrDuplicate) {
		writeError(w, r, http.StatusConflict, "duplicate_order", err.Error(), nil)
		return
	}
	if err != nil {
		s.log.Error("create order", "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not create order", nil)
		return
	}
	s.record(r.Context(), audit.OrderCreated, "order", created.ID, audit.OutcomeSuccess, map[string]any{
		"parcel_number": created.ParcelNumber, "state": created.State, "county": created.County, "tax_year": created.TaxYear,
		"order_client_id": created.ClientID,
	})
	w.Header().Set("Location", "/v1/orders/"+created.ID)
	writeJSON(w, http.StatusCreated, created)
}

func (s *Server) getOrder(w http.ResponseWriter, r *http.Request) {
	o, _, ok := s.loadOrder(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, o)
}

func (s *Server) listOrders(w http.ResponseWriter, r *http.Request) {
	p := principalFrom(r.Context())
	q := r.URL.Query()
	f := store.OrderFilter{Limit: 50}
	if v := q.Get("status"); v != "" {
		st := model.OrderStatus(strings.ToUpper(v))
		if !st.Valid() {
			writeError(w, r, http.StatusBadRequest, "invalid_query", "unknown status filter", nil)
			return
		}
		f.Status = st
	}
	if v := q.Get("limit"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 1 || n > 200 {
			writeError(w, r, http.StatusBadRequest, "invalid_query", "limit must be between 1 and 200", nil)
			return
		}
		f.Limit = n
	}
	if v := q.Get("offset"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n < 0 {
			writeError(w, r, http.StatusBadRequest, "invalid_query", "offset must be a non-negative integer", nil)
			return
		}
		f.Offset = n
	}
	if p.Staff() {
		f.ClientID = strings.TrimSpace(q.Get("client_id"))
	} else {
		f.ClientID = p.ClientID // clients can only ever list their own orders
	}
	orders := s.store.ListOrders(f)
	if orders == nil {
		orders = []model.Order{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"orders": orders, "count": len(orders), "limit": f.Limit, "offset": f.Offset})
}

func (s *Server) updateOrder(w http.ResponseWriter, r *http.Request) {
	o, p, ok := s.loadOrder(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var req updateOrderRequest
	if !s.decode(w, r, s.cfg.MaxBodyBytes, &req) {
		return
	}
	in := validation.Normalize(req.OrderInput)
	errs := validation.ValidateOrderInput(in, s.now())
	if req.Version < 1 {
		errs = append(errs, validation.FieldError{Field: "version", Code: "required", Message: "version of the order being edited is required"})
	}
	if len(errs) > 0 {
		s.record(r.Context(), audit.OrderValidationFailed, "order", o.ID, audit.OutcomeFailure, map[string]any{"stage": "update", "error_count": len(errs)})
		writeValidation(w, r, errs)
		return
	}

	var changed []string
	var from model.OrderStatus
	updated, err := s.store.UpdateOrder(o.ID, func(cur *model.Order) error {
		if cur.Version != req.Version {
			return errVersionConflict
		}
		if cur.Status != model.OrderCreated && cur.Status != model.OrderValidated {
			return errNotEditable
		}
		changed = changedFields(*cur, in)
		if len(changed) == 0 {
			return errNoChange
		}
		from = cur.Status
		cur.ParcelNumber, cur.PropertyAddress, cur.State = in.ParcelNumber, in.PropertyAddress, in.State
		cur.County, cur.Jurisdiction, cur.TaxYear, cur.OwnerName = in.County, in.Jurisdiction, in.TaxYear, in.OwnerName
		if cur.Status == model.OrderValidated { // edits invalidate earlier validation
			// Deliberately not a normal transition: this is the only permitted way back to CREATED.
			cur.StatusHistory = append(cur.StatusHistory, model.StatusChange{
				From: string(model.OrderValidated), To: string(model.OrderCreated), At: s.now(), By: p.Actor,
				Reason: "order modified; revalidation required"})
			cur.Status = model.OrderCreated
		}
		return nil
	})
	switch {
	case errors.Is(err, errNoChange):
		writeJSON(w, http.StatusOK, o)
		return
	case errors.Is(err, errVersionConflict):
		writeError(w, r, http.StatusConflict, "version_conflict", "the order was modified by someone else; reload and retry", nil)
		return
	case errors.Is(err, errNotEditable):
		writeError(w, r, http.StatusConflict, "not_editable", "orders can only be edited while CREATED or VALIDATED", nil)
		return
	case err != nil:
		s.log.Error("update order", "error", err)
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not update order", nil)
		return
	}
	s.record(r.Context(), audit.OrderUpdated, "order", updated.ID, audit.OutcomeSuccess, map[string]any{
		"changed_fields": changed, "previous_status": string(from), "new_version": updated.Version,
	})
	writeJSON(w, http.StatusOK, updated)
}

// validateOrder runs the stricter pre-processing rules and, on success, moves CREATED -> VALIDATED.
func (s *Server) validateOrder(w http.ResponseWriter, r *http.Request) {
	o, p, ok := s.loadOrder(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if o.Status == model.OrderValidated {
		writeJSON(w, http.StatusOK, o) // idempotent
		return
	}
	if o.Status != model.OrderCreated {
		writeError(w, r, http.StatusConflict, "invalid_status", "only CREATED orders can be validated", nil)
		return
	}
	if errs := validation.ValidateForProcessing(inputOf(o), s.now()); len(errs) > 0 {
		s.record(r.Context(), audit.OrderValidationFailed, "order", o.ID, audit.OutcomeFailure, map[string]any{"stage": "validate", "error_count": len(errs)})
		writeValidation(w, r, errs)
		return
	}
	updated, err := s.store.UpdateOrder(o.ID, func(cur *model.Order) error {
		if cur.Status == model.OrderValidated {
			return errNoChange
		}
		return applyOrderTransition(cur, model.OrderValidated, p.Actor, "passed processing validation", s.now())
	})
	if errors.Is(err, errNoChange) {
		writeJSON(w, http.StatusOK, o)
		return
	}
	if errors.Is(err, errBadTransition) {
		writeError(w, r, http.StatusConflict, "invalid_status", "order status changed concurrently", nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not validate order", nil)
		return
	}
	s.record(r.Context(), audit.OrderValidated, "order", updated.ID, audit.OutcomeSuccess, nil)
	s.afterOrderStatus(r.Context(), updated)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) changeOrderStatus(w http.ResponseWriter, r *http.Request) {
	o, p, ok := s.loadOrder(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	var req statusRequest
	if !s.decode(w, r, s.cfg.MaxBodyBytes, &req) {
		return
	}
	to := model.OrderStatus(strings.ToUpper(strings.TrimSpace(req.Status)))
	if !to.Valid() {
		writeValidation(w, r, validation.Errors{{Field: "status", Code: "invalid_value", Message: "unknown order status"}})
		return
	}
	if to == model.OrderValidated {
		writeError(w, r, http.StatusBadRequest, "use_validate", "use POST /v1/orders/{id}/validate to validate an order", nil)
		return
	}
	if !p.Staff() && to != model.OrderCancelled {
		s.record(r.Context(), audit.AccessDenied, "order", o.ID, audit.OutcomeDenied, map[string]any{"reason": "clients may only cancel", "requested_status": string(to)})
		writeError(w, r, http.StatusForbidden, "forbidden", "clients may only cancel their own orders", nil)
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if len(reason) > 500 {
		writeValidation(w, r, validation.Errors{{Field: "reason", Code: "invalid_length", Message: "reason must be 500 characters or fewer"}})
		return
	}

	var from model.OrderStatus
	updated, err := s.store.UpdateOrder(o.ID, func(cur *model.Order) error {
		from = cur.Status
		return applyOrderTransition(cur, to, p.Actor, reason, s.now())
	})
	if errors.Is(err, errBadTransition) {
		s.record(r.Context(), audit.OrderStatusChanged, "order", o.ID, audit.OutcomeFailure, map[string]any{"from": string(o.Status), "to": string(to), "error": err.Error()})
		writeError(w, r, http.StatusConflict, "invalid_transition", err.Error(), nil)
		return
	}
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not change status", nil)
		return
	}
	s.record(r.Context(), audit.OrderStatusChanged, "order", updated.ID, audit.OutcomeSuccess, map[string]any{"from": string(from), "to": string(to), "reason": reason})
	s.afterOrderStatus(r.Context(), updated)
	writeJSON(w, http.StatusOK, updated)
}

func (s *Server) getOrderStatus(w http.ResponseWriter, r *http.Request) {
	o, _, ok := s.loadOrder(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	certs := s.store.ListCertificates(o.ID)
	summary := make([]map[string]any, 0, len(certs))
	for _, c := range certs {
		summary = append(summary, map[string]any{"id": c.ID, "type": c.Type, "status": c.Status})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"order_id": o.ID, "status": o.Status, "external_ref": o.ExternalRef, "version": o.Version,
		"updated_at": o.UpdatedAt, "history": o.StatusHistory, "certificates": summary,
	})
}

// afterOrderStatus performs integration side effects without blocking the HTTP response.
//   - entering IN_PROGRESS submits the order to the downstream tax system; if that fails after all
//     retries the order is moved to FAILED so staff can see it and retry;
//   - every change is published to the title/closing platform.
func (s *Server) afterOrderStatus(parent context.Context, o model.Order) {
	s.background(parent, func(ctx context.Context) {
		if o.Status == model.OrderInProgress {
			ref, err := s.integ.Submit(ctx, o)
			if err != nil {
				failed, uerr := s.store.UpdateOrder(o.ID, func(cur *model.Order) error {
					if cur.Status != model.OrderInProgress {
						return errBadTransition
					}
					return applyOrderTransition(cur, model.OrderFailed, "system", "downstream tax-system submission failed", s.now())
				})
				if uerr == nil {
					s.record(ctx, audit.OrderStatusChanged, "order", o.ID, audit.OutcomeSuccess, map[string]any{
						"from": string(model.OrderInProgress), "to": string(model.OrderFailed), "reason": "downstream submission failed", "actor_type": "system"})
					_ = failed
				}
			} else if ref != "" {
				_, _ = s.store.UpdateOrder(o.ID, func(cur *model.Order) error { cur.ExternalRef = ref; return nil })
			}
		}
		latest, err := s.store.GetOrder(o.ID)
		if err != nil {
			return
		}
		if err := s.integ.NotifyStatus(ctx, latest); err != nil {
			s.log.Warn("status notification failed", "order_id", o.ID, "error", err.Error())
		}
	})
}
