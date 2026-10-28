package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"

	"uts-tax-service/internal/audit"
	"uts-tax-service/internal/model"
	"uts-tax-service/internal/validation"
)

// UTS-GO-103: secure retrieval of tax and property documents for completed orders.
//
// Security properties:
//   - bearer authentication on every route (middleware);
//   - tenant isolation: a client can only reach documents of its own orders (404 otherwise);
//   - documents are retrievable only once the order is COMPLETED;
//   - downloads are forced to attachments with nosniff, no-store and an integrity checksum;
//   - every list/download (and every denied attempt) is audited without logging document bytes.

var (
	docNameRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._()\-]{0,127}$`)

	allowedDocTypes = map[string]struct{}{
		"application/pdf": {}, "image/png": {}, "image/jpeg": {}, "text/plain": {}, "text/csv": {},
	}
)

type uploadDocumentRequest struct {
	Name          string `json:"name"`
	ContentType   string `json:"content_type"`
	ContentBase64 string `json:"content_base64"`
}

// magicMatches verifies the bytes really are what the caller claims (defence against disguised uploads).
func magicMatches(ct string, b []byte) bool {
	switch ct {
	case "application/pdf":
		return bytes.HasPrefix(b, []byte("%PDF-"))
	case "image/png":
		return bytes.HasPrefix(b, []byte("\x89PNG\r\n\x1a\n"))
	case "image/jpeg":
		return bytes.HasPrefix(b, []byte{0xFF, 0xD8, 0xFF})
	case "text/plain", "text/csv":
		return utf8.Valid(b) && !bytes.Contains(b, []byte{0})
	}
	return false
}

// uploadDocument lets staff attach fulfilment documents to an order.
func (s *Server) uploadDocument(w http.ResponseWriter, r *http.Request) {
	o, p, ok := s.loadOrder(w, r, r.PathValue("id"))
	if !ok {
		return
	}
	if !s.requireStaff(w, r, p, "order", o.ID) {
		return
	}
	if o.Status == model.OrderCancelled {
		writeError(w, r, http.StatusConflict, "order_cancelled", "cannot attach documents to a cancelled order", nil)
		return
	}
	var req uploadDocumentRequest
	limit := int64(s.cfg.MaxDocBytes)*4/3 + 4096 // base64 inflates by ~4/3
	if !s.decode(w, r, limit, &req) {
		return
	}
	req.Name = strings.TrimSpace(req.Name)
	req.ContentType = strings.ToLower(strings.TrimSpace(req.ContentType))

	var errs validation.Errors
	if !docNameRe.MatchString(req.Name) || strings.Contains(req.Name, "..") {
		errs = append(errs, validation.FieldError{Field: "name", Code: "invalid_format", Message: "name must be 1-128 characters: letters, digits, space, '.', '_', '-', '(' or ')'"})
	}
	if _, ok := allowedDocTypes[req.ContentType]; !ok {
		errs = append(errs, validation.FieldError{Field: "content_type", Code: "unsupported", Message: "content_type must be one of application/pdf, image/png, image/jpeg, text/plain, text/csv"})
	}
	data, err := base64.StdEncoding.DecodeString(req.ContentBase64)
	switch {
	case err != nil || len(data) == 0:
		errs = append(errs, validation.FieldError{Field: "content_base64", Code: "invalid_value", Message: "content_base64 must be non-empty, standard base64"})
	case len(data) > s.cfg.MaxDocBytes:
		errs = append(errs, validation.FieldError{Field: "content_base64", Code: "too_large", Message: "document exceeds the maximum allowed size of " + strconv.Itoa(s.cfg.MaxDocBytes) + " bytes"})
	case len(errs) == 0 && !magicMatches(req.ContentType, data):
		errs = append(errs, validation.FieldError{Field: "content_base64", Code: "content_mismatch", Message: "file contents do not match the declared content_type"})
	}
	if len(errs) > 0 {
		writeValidation(w, r, errs)
		return
	}

	sum := sha256.Sum256(data)
	doc, err := s.store.AddDocument(model.Document{
		ID: model.NewID("doc"), OrderID: o.ID, Name: req.Name, ContentType: req.ContentType, Size: len(data),
		SHA256: hex.EncodeToString(sum[:]), UploadedBy: p.Actor, CreatedAt: s.now(), Content: data,
	})
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not store document", nil)
		return
	}
	s.record(r.Context(), audit.DocumentUploaded, "document", doc.ID, audit.OutcomeSuccess, map[string]any{
		"order_id": o.ID, "name": doc.Name, "content_type": doc.ContentType, "size": doc.Size, "sha256": doc.SHA256,
	})
	doc.Content = nil
	w.Header().Set("Location", "/v1/orders/"+o.ID+"/documents/"+doc.ID)
	writeJSON(w, http.StatusCreated, doc)
}

func (s *Server) requireCompleted(w http.ResponseWriter, r *http.Request, o model.Order) bool {
	if o.Status == model.OrderCompleted {
		return true
	}
	writeError(w, r, http.StatusConflict, "order_not_completed", "documents are available only for COMPLETED orders", map[string]string{"status": string(o.Status)})
	return false
}

func (s *Server) listDocuments(w http.ResponseWriter, r *http.Request) {
	o, _, ok := s.loadOrder(w, r, r.PathValue("id"))
	if !ok || !s.requireCompleted(w, r, o) {
		return
	}
	docs := s.store.ListDocuments(o.ID)
	if docs == nil {
		docs = []model.Document{}
	}
	s.record(r.Context(), audit.DocumentListed, "order", o.ID, audit.OutcomeSuccess, map[string]any{"document_count": len(docs)})
	writeJSON(w, http.StatusOK, map[string]any{"documents": docs, "count": len(docs)})
}

func (s *Server) downloadDocument(w http.ResponseWriter, r *http.Request) {
	o, _, ok := s.loadOrder(w, r, r.PathValue("id"))
	if !ok || !s.requireCompleted(w, r, o) {
		return
	}
	docID := r.PathValue("docID")
	doc, err := s.store.GetDocument(docID)
	if err != nil || doc.OrderID != o.ID { // a doc id from another order must not leak
		if err == nil {
			s.record(r.Context(), audit.AccessDenied, "document", docID, audit.OutcomeDenied, map[string]any{"reason": "document does not belong to order", "order_id": o.ID})
		}
		writeError(w, r, http.StatusNotFound, "not_found", "document not found", nil)
		return
	}
	s.record(r.Context(), audit.DocumentAccessed, "document", doc.ID, audit.OutcomeSuccess, map[string]any{
		"order_id": o.ID, "name": doc.Name, "size": doc.Size, "sha256": doc.SHA256,
	})
	h := w.Header()
	h.Set("Content-Type", doc.ContentType)
	h.Set("Content-Length", strconv.Itoa(len(doc.Content)))
	h.Set("Content-Disposition", mime.FormatMediaType("attachment", map[string]string{"filename": doc.Name}))
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "private, no-store")
	h.Set("ETag", `"`+doc.SHA256+`"`)
	h.Set("X-Content-SHA256", doc.SHA256)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(doc.Content)
}
