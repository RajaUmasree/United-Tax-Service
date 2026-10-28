package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"uts-tax-service/internal/audit"
	"uts-tax-service/internal/model"
	"uts-tax-service/internal/store"
)

const (
	adminTok  = "admin-token-0123456789"
	opsTok    = "ops-token-0123456789ab"
	acmeTok   = "acme-token-0123456789a"
	globexTok = "globex-token-0123456789"
)

// fakeIntegrations records calls and can be told to fail.
type fakeIntegrations struct {
	mu        sync.Mutex
	submitted []string
	notified  []model.OrderStatus
	submitErr error
}

func (f *fakeIntegrations) NotifyStatus(_ context.Context, o model.Order) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.notified = append(f.notified, o.Status)
	return nil
}

func (f *fakeIntegrations) Submit(_ context.Context, o model.Order) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.submitErr != nil {
		return "", f.submitErr
	}
	f.submitted = append(f.submitted, o.ID)
	return "TX-REF-1", nil
}

type env struct {
	t     *testing.T
	srv   *Server
	ts    *httptest.Server
	rec   *audit.MemoryRecorder
	integ *fakeIntegrations
	store *store.Memory
}

func newEnv(t *testing.T) *env {
	t.Helper()
	tokens, err := ParseTokens(strings.Join([]string{
		adminTok + ":alice:admin",
		opsTok + ":olivia:ops",
		acmeTok + ":acme-bot:client:acme",
		globexTok + ":globex-bot:client:globex",
	}, ","))
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, rec: &audit.MemoryRecorder{}, integ: &fakeIntegrations{}, store: store.NewMemory()}
	e.srv = New(e.store, e.integ, e.rec, tokens, slog.New(slog.NewTextHandler(io.Discard, nil)), Config{MaxDocBytes: 1 << 20})
	e.ts = httptest.NewServer(e.srv.Handler())
	t.Cleanup(func() { e.srv.Wait(); e.ts.Close() })
	return e
}

func (e *env) do(method, path, token string, body any) (int, http.Header, []byte) {
	e.t.Helper()
	var rdr io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rdr = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, e.ts.URL+path, rdr)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		e.t.Fatal(err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, resp.Header, data
}

func decode[T any](t *testing.T, b []byte) T {
	t.Helper()
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
	return v
}

func validOrder() map[string]any {
	return map[string]any{
		"parcel_number": "r-12345.001", "property_address": "100 Main St, Bentonville", "state": "ar",
		"county": "Benton", "jurisdiction": "Benton County Collector", "tax_year": 2025, "owner_name": "Jane Q. Public",
	}
}

func (e *env) createOrder(token string, mutate func(map[string]any)) model.Order {
	e.t.Helper()
	body := validOrder()
	if mutate != nil {
		mutate(body)
	}
	code, _, data := e.do("POST", "/v1/orders", token, body)
	if code != http.StatusCreated {
		e.t.Fatalf("create order: %d %s", code, data)
	}
	return decode[model.Order](e.t, data)
}

func (e *env) status(token, id, to string) (int, []byte) {
	code, _, data := e.do("PATCH", "/v1/orders/"+id+"/status", token, map[string]string{"status": to})
	return code, data
}

// completeOrder drives an order CREATED -> VALIDATED -> IN_PROGRESS -> COMPLETED.
func (e *env) completeOrder(id string) {
	e.t.Helper()
	if code, _, d := e.do("POST", "/v1/orders/"+id+"/validate", opsTok, nil); code != 200 {
		e.t.Fatalf("validate: %d %s", code, d)
	}
	for _, st := range []string{"IN_PROGRESS", "COMPLETED"} {
		if code, d := e.status(opsTok, id, st); code != 200 {
			e.t.Fatalf("-> %s: %d %s", st, code, d)
		}
	}
	e.srv.Wait()
}

// ---------- UTS-GO-101 ----------

func TestAuth_RejectsMissingAndBadTokens(t *testing.T) {
	e := newEnv(t)
	for _, tok := range []string{"", "wrong-token-0000000000"} {
		code, hdr, _ := e.do("GET", "/v1/orders", tok, nil)
		if code != http.StatusUnauthorized || hdr.Get("WWW-Authenticate") == "" {
			t.Fatalf("token %q: got %d", tok, code)
		}
	}
	if len(e.rec.Find(audit.AuthFailed)) != 2 {
		t.Fatalf("auth failures not audited: %+v", e.rec.Events())
	}
	for _, ev := range e.rec.Events() {
		if strings.Contains(toJSON(ev), "wrong-token") {
			t.Fatal("bad token leaked into audit log")
		}
	}
	if code, _, _ := e.do("GET", "/healthz", "", nil); code != 200 {
		t.Fatalf("healthz should be public, got %d", code)
	}
}

func toJSON(v any) string { b, _ := json.Marshal(v); return string(b) }

func TestCreateOrder_NormalisesAndAudits(t *testing.T) {
	e := newEnv(t)
	code, hdr, data := e.do("POST", "/v1/orders", acmeTok, validOrder())
	if code != http.StatusCreated {
		t.Fatalf("%d %s", code, data)
	}
	o := decode[model.Order](t, data)
	if o.ParcelNumber != "R-12345.001" || o.State != "AR" || o.ClientID != "acme" ||
		o.Status != model.OrderCreated || o.Version != 1 || len(o.StatusHistory) != 1 {
		t.Fatalf("unexpected order: %+v", o)
	}
	if hdr.Get("Location") != "/v1/orders/"+o.ID || hdr.Get("X-Request-ID") == "" {
		t.Fatalf("headers: %v", hdr)
	}
	evs := e.rec.Find(audit.OrderCreated)
	if len(evs) != 1 || evs[0].Actor != "acme-bot" || evs[0].ResourceID != o.ID || evs[0].RequestID == "" {
		t.Fatalf("audit: %+v", evs)
	}
}

func TestCreateOrder_ValidationErrors(t *testing.T) {
	e := newEnv(t)
	body := validOrder()
	body["state"] = "ZZ"
	body["tax_year"] = 1800
	code, _, data := e.do("POST", "/v1/orders", acmeTok, body)
	if code != http.StatusUnprocessableEntity {
		t.Fatalf("%d %s", code, data)
	}
	var resp struct {
		Error struct {
			Code    string `json:"code"`
			Details []struct{ Field string }
		}
	}
	_ = json.Unmarshal(data, &resp)
	if resp.Error.Code != "validation_failed" || len(resp.Error.Details) != 2 {
		t.Fatalf("unexpected error body: %s", data)
	}
	if len(e.rec.Find(audit.OrderValidationFailed)) != 1 {
		t.Fatal("validation failure not audited")
	}
}

func TestCreateOrder_RejectsUnknownFieldsAndBadJSON(t *testing.T) {
	e := newEnv(t)
	body := validOrder()
	body["status"] = "COMPLETED" // mass-assignment attempt
	if code, _, _ := e.do("POST", "/v1/orders", acmeTok, body); code != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d", code)
	}
	req, _ := http.NewRequest("POST", e.ts.URL+"/v1/orders", strings.NewReader("{not json"))
	req.Header.Set("Authorization", "Bearer "+acmeTok)
	resp, _ := http.DefaultClient.Do(req)
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("bad json: %d", resp.StatusCode)
	}
}

func TestCreateOrder_BodyTooLarge(t *testing.T) {
	e := newEnv(t)
	body := validOrder()
	body["property_address"] = strings.Repeat("x", 2<<20)
	if code, _, _ := e.do("POST", "/v1/orders", acmeTok, body); code != http.StatusRequestEntityTooLarge {
		t.Fatalf("got %d", code)
	}
}

func TestCreateOrder_DuplicateIsConflictButAllowedAfterCancel(t *testing.T) {
	e := newEnv(t)
	first := e.createOrder(acmeTok, nil)
	if code, _, _ := e.do("POST", "/v1/orders", acmeTok, validOrder()); code != http.StatusConflict {
		t.Fatalf("duplicate: %d", code)
	}
	// a different client may order the same parcel
	e.createOrder(globexTok, nil)
	if code, _ := e.status(acmeTok, first.ID, "CANCELLED"); code != 200 {
		t.Fatalf("cancel: %d", code)
	}
	e.createOrder(acmeTok, nil)
}

func TestCreateOrder_StaffMustSupplyClientID(t *testing.T) {
	e := newEnv(t)
	if code, _, _ := e.do("POST", "/v1/orders", opsTok, validOrder()); code != http.StatusUnprocessableEntity {
		t.Fatalf("got %d", code)
	}
	o := e.createOrder(opsTok, func(m map[string]any) { m["client_id"] = "acme" })
	if o.ClientID != "acme" || o.CreatedBy != "olivia" {
		t.Fatalf("%+v", o)
	}
	// a client cannot create orders on behalf of another client
	o2 := e.createOrder(globexTok, func(m map[string]any) { m["client_id"] = "acme"; m["parcel_number"] = "ZZ-999" })
	if o2.ClientID != "globex" {
		t.Fatalf("client_id override honoured for client: %+v", o2)
	}
}

func TestTenantIsolation(t *testing.T) {
	e := newEnv(t)
	o := e.createOrder(acmeTok, nil)
	for _, path := range []string{"/v1/orders/" + o.ID, "/v1/orders/" + o.ID + "/status", "/v1/orders/" + o.ID + "/certificates"} {
		if code, _, _ := e.do("GET", path, globexTok, nil); code != http.StatusNotFound {
			t.Fatalf("%s leaked across tenants: %d", path, code)
		}
	}
	if len(e.rec.Find(audit.AccessDenied)) == 0 {
		t.Fatal("cross-tenant access not audited")
	}
	_, _, data := e.do("GET", "/v1/orders", globexTok, nil)
	if got := decode[struct{ Count int }](t, data).Count; got != 0 {
		t.Fatalf("globex sees %d orders", got)
	}
	_, _, data = e.do("GET", "/v1/orders", acmeTok, nil)
	if got := decode[struct{ Count int }](t, data).Count; got != 1 {
		t.Fatalf("acme sees %d orders", got)
	}
	_, _, data = e.do("GET", "/v1/orders", adminTok, nil)
	if got := decode[struct{ Count int }](t, data).Count; got != 1 {
		t.Fatalf("admin sees %d orders", got)
	}
}

func TestListOrders_Filters(t *testing.T) {
	e := newEnv(t)
	e.createOrder(acmeTok, nil)
	e.createOrder(acmeTok, func(m map[string]any) { m["parcel_number"] = "R-777" })
	if code, _, _ := e.do("GET", "/v1/orders?status=bogus", acmeTok, nil); code != 400 {
		t.Fatalf("bad status filter: %d", code)
	}
	if code, _, _ := e.do("GET", "/v1/orders?limit=0", acmeTok, nil); code != 400 {
		t.Fatalf("bad limit: %d", code)
	}
	_, _, data := e.do("GET", "/v1/orders?status=created&limit=1", acmeTok, nil)
	if got := decode[struct{ Count int }](t, data).Count; got != 1 {
		t.Fatalf("limit not applied: %d", got)
	}
}

func TestUpdateOrder_OptimisticConcurrencyAndRevalidation(t *testing.T) {
	e := newEnv(t)
	o := e.createOrder(acmeTok, nil)
	if code, _, _ := e.do("POST", "/v1/orders/"+o.ID+"/validate", acmeTok, nil); code != 200 {
		t.Fatal("validate failed")
	}
	cur := decode[model.Order](t, mustGet(t, e, acmeTok, "/v1/orders/"+o.ID))
	if cur.Status != model.OrderValidated {
		t.Fatalf("status %s", cur.Status)
	}

	upd := validOrder()
	upd["property_address"] = "200 Oak Ave, Bentonville"
	upd["version"] = cur.Version
	code, _, data := e.do("PUT", "/v1/orders/"+o.ID, acmeTok, upd)
	if code != 200 {
		t.Fatalf("update: %d %s", code, data)
	}
	after := decode[model.Order](t, data)
	if after.PropertyAddress != "200 Oak Ave, Bentonville" || after.Status != model.OrderCreated || after.Version != cur.Version+1 {
		t.Fatalf("expected revalidation reset: %+v", after)
	}
	ev := e.rec.Find(audit.OrderUpdated)
	if len(ev) != 1 || toJSON(ev[0].Details["changed_fields"]) != `["property_address"]` {
		t.Fatalf("audit: %+v", ev)
	}

	// stale version
	if code, _, _ := e.do("PUT", "/v1/orders/"+o.ID, acmeTok, upd); code != http.StatusConflict {
		t.Fatalf("stale update should conflict: %d", code)
	}
	// missing version
	delete(upd, "version")
	if code, _, _ := e.do("PUT", "/v1/orders/"+o.ID, acmeTok, upd); code != http.StatusUnprocessableEntity {
		t.Fatalf("missing version: %d", code)
	}
}

func mustGet(t *testing.T, e *env, tok, path string) []byte {
	t.Helper()
	code, _, data := e.do("GET", path, tok, nil)
	if code != 200 {
		t.Fatalf("GET %s: %d %s", path, code, data)
	}
	return data
}

func TestUpdateOrder_NoChangeAndNotEditable(t *testing.T) {
	e := newEnv(t)
	o := e.createOrder(acmeTok, nil)
	same := validOrder()
	same["parcel_number"], same["state"] = "R-12345.001", "AR"
	same["version"] = o.Version
	code, _, data := e.do("PUT", "/v1/orders/"+o.ID, acmeTok, same)
	if code != 200 || decode[model.Order](t, data).Version != o.Version {
		t.Fatalf("no-op update should not bump version: %d %s", code, data)
	}
	e.completeOrder(o.ID)
	cur := decode[model.Order](t, mustGet(t, e, acmeTok, "/v1/orders/"+o.ID))
	upd := validOrder()
	upd["property_address"] = "999 Different Rd"
	upd["version"] = cur.Version
	if code, _, _ := e.do("PUT", "/v1/orders/"+o.ID, acmeTok, upd); code != http.StatusConflict {
		t.Fatalf("completed order must not be editable: %d", code)
	}
}

func TestValidateOrder_ProcessingRules(t *testing.T) {
	e := newEnv(t)
	o := e.createOrder(acmeTok, func(m map[string]any) { delete(m, "owner_name") })
	code, _, data := e.do("POST", "/v1/orders/"+o.ID+"/validate", acmeTok, nil)
	if code != http.StatusUnprocessableEntity || !strings.Contains(string(data), "owner_name") {
		t.Fatalf("owner should be required before processing: %d %s", code, data)
	}
	cur := decode[model.Order](t, mustGet(t, e, acmeTok, "/v1/orders/"+o.ID))
	if cur.Status != model.OrderCreated {
		t.Fatal("failed validation must not change status")
	}
	// idempotent success path
	o2 := e.createOrder(acmeTok, func(m map[string]any) { m["parcel_number"] = "R-2" })
	for i := 0; i < 2; i++ {
		if code, _, d := e.do("POST", "/v1/orders/"+o2.ID+"/validate", acmeTok, nil); code != 200 {
			t.Fatalf("validate #%d: %d %s", i, code, d)
		}
	}
	if len(e.rec.Find(audit.OrderValidated)) != 1 {
		t.Fatal("expected exactly one validated audit event")
	}
}

func TestOrderStatusMachine(t *testing.T) {
	e := newEnv(t)
	o := e.createOrder(acmeTok, nil)

	if code, _ := e.status(opsTok, o.ID, "COMPLETED"); code != http.StatusConflict {
		t.Fatalf("CREATED->COMPLETED must be rejected: %d", code)
	}
	if code, _ := e.status(opsTok, o.ID, "VALIDATED"); code != http.StatusBadRequest {
		t.Fatalf("VALIDATED must go through /validate: %d", code)
	}
	if code, _ := e.status(opsTok, o.ID, "NONSENSE"); code != http.StatusUnprocessableEntity {
		t.Fatalf("unknown status: %d", code)
	}
	if code, _ := e.status(acmeTok, o.ID, "IN_PROGRESS"); code != http.StatusForbidden {
		t.Fatalf("clients may only cancel: %d", code)
	}
	e.completeOrder(o.ID)
	if code, _ := e.status(opsTok, o.ID, "CANCELLED"); code != http.StatusConflict {
		t.Fatalf("COMPLETED is terminal: %d", code)
	}

	code, _, data := e.do("GET", "/v1/orders/"+o.ID+"/status", acmeTok, nil)
	st := decode[struct {
		Status  string
		History []model.StatusChange
	}](t, data)
	if code != 200 || st.Status != "COMPLETED" || len(st.History) != 4 {
		t.Fatalf("status tracking: %d %s", code, data)
	}
	okChanges, failedChanges := 0, 0
	for _, ev := range e.rec.Find(audit.OrderStatusChanged) {
		if ev.Outcome == audit.OutcomeSuccess {
			okChanges++
		} else {
			failedChanges++
		}
	}
	if okChanges != 2 || failedChanges != 2 { // 2 real transitions, 2 rejected attempts
		t.Fatalf("status change audits: success=%d failure=%d", okChanges, failedChanges)
	}
}

func TestIntegrations_SubmittedOnInProgressAndNotified(t *testing.T) {
	e := newEnv(t)
	o := e.createOrder(acmeTok, nil)
	e.completeOrder(o.ID)

	cur := decode[model.Order](t, mustGet(t, e, adminTok, "/v1/orders/"+o.ID))
	if cur.ExternalRef != "TX-REF-1" {
		t.Fatalf("external ref not stored: %+v", cur)
	}
	e.integ.mu.Lock()
	defer e.integ.mu.Unlock()
	if len(e.integ.submitted) != 1 || e.integ.submitted[0] != o.ID {
		t.Fatalf("submitted: %v", e.integ.submitted)
	}
	if len(e.integ.notified) < 3 { // VALIDATED, IN_PROGRESS, COMPLETED
		t.Fatalf("notified: %v", e.integ.notified)
	}
}

func TestIntegrations_SubmitFailureMovesOrderToFailedThenRetry(t *testing.T) {
	e := newEnv(t)
	e.integ.submitErr = errors.New("tax system down")
	o := e.createOrder(acmeTok, nil)
	e.do("POST", "/v1/orders/"+o.ID+"/validate", opsTok, nil)
	if code, _ := e.status(opsTok, o.ID, "IN_PROGRESS"); code != 200 {
		t.Fatal("transition failed")
	}
	e.srv.Wait()
	cur := decode[model.Order](t, mustGet(t, e, adminTok, "/v1/orders/"+o.ID))
	if cur.Status != model.OrderFailed {
		t.Fatalf("expected FAILED after downstream failure, got %s", cur.Status)
	}
	last := cur.StatusHistory[len(cur.StatusHistory)-1]
	if last.By != "system" || strings.Contains(last.Reason, "unavailable") {
		t.Fatalf("system history entry wrong/leaky: %+v", last)
	}

	// downstream recovers; staff retry
	e.integ.mu.Lock()
	e.integ.submitErr = nil
	e.integ.mu.Unlock()
	if code, _ := e.status(opsTok, o.ID, "IN_PROGRESS"); code != 200 {
		t.Fatal("retry transition failed")
	}
	e.srv.Wait()
	cur = decode[model.Order](t, mustGet(t, e, adminTok, "/v1/orders/"+o.ID))
	if cur.Status != model.OrderInProgress || cur.ExternalRef != "TX-REF-1" {
		t.Fatalf("retry result: %+v", cur)
	}
}

// ---------- UTS-GO-102 ----------

func TestCertificateLifecycle(t *testing.T) {
	e := newEnv(t)
	o := e.createOrder(acmeTok, nil)

	// order not ready yet
	if code, _, _ := e.do("POST", "/v1/orders/"+o.ID+"/certificates", acmeTok, map[string]string{"type": "CURRENT_TAX"}); code != http.StatusConflict {
		t.Fatalf("cert on CREATED order: %d", code)
	}
	e.do("POST", "/v1/orders/"+o.ID+"/validate", acmeTok, nil)

	if code, _, _ := e.do("POST", "/v1/orders/"+o.ID+"/certificates", acmeTok, map[string]string{"type": "BOGUS"}); code != http.StatusUnprocessableEntity {
		t.Fatalf("bad type: %d", code)
	}
	code, hdr, data := e.do("POST", "/v1/orders/"+o.ID+"/certificates", acmeTok, map[string]string{"type": "current_tax", "notes": "rush"})
	if code != http.StatusCreated {
		t.Fatalf("create cert: %d %s", code, data)
	}
	c := decode[model.Certificate](t, data)
	if c.Status != model.CertRequested || c.Type != "CURRENT_TAX" || hdr.Get("Location") != "/v1/certificates/"+c.ID {
		t.Fatalf("%+v", c)
	}
	// duplicate open request
	if code, _, _ := e.do("POST", "/v1/orders/"+o.ID+"/certificates", acmeTok, map[string]string{"type": "CURRENT_TAX"}); code != http.StatusConflict {
		t.Fatalf("duplicate open cert: %d", code)
	}

	patch := func(tok, to string) int {
		code, _, _ := e.do("PATCH", "/v1/certificates/"+c.ID+"/status", tok, map[string]string{"status": to})
		return code
	}
	if patch(opsTok, "ISSUED") != http.StatusConflict {
		t.Fatal("REQUESTED->ISSUED must be rejected")
	}
	if patch(acmeTok, "IN_REVIEW") != http.StatusForbidden {
		t.Fatal("clients may not advance certificates")
	}
	if patch(globexTok, "CANCELLED") != http.StatusNotFound {
		t.Fatal("other tenant must not reach certificate")
	}
	if patch(opsTok, "IN_REVIEW") != 200 || patch(opsTok, "ISSUED") != 200 {
		t.Fatal("happy path failed")
	}
	if patch(opsTok, "CANCELLED") != http.StatusConflict {
		t.Fatal("ISSUED is terminal")
	}

	final := decode[model.Certificate](t, mustGet(t, e, acmeTok, "/v1/certificates/"+c.ID))
	if final.Status != model.CertIssued || len(final.StatusHistory) != 3 || final.Version != 3 {
		t.Fatalf("%+v", final)
	}
	_, _, data = e.do("GET", "/v1/orders/"+o.ID+"/status", acmeTok, nil)
	if !strings.Contains(string(data), `"ISSUED"`) {
		t.Fatalf("order status should summarise certificates: %s", data)
	}
	if len(e.rec.Find(audit.CertificateRequested)) != 1 || len(e.rec.Find(audit.CertificateStatusChanged)) < 3 {
		t.Fatalf("certificate audits missing: %+v", e.rec.Events())
	}
}

func TestCertificate_RejectedCanBeResubmitted(t *testing.T) {
	e := newEnv(t)
	o := e.createOrder(acmeTok, nil)
	e.do("POST", "/v1/orders/"+o.ID+"/validate", acmeTok, nil)
	_, _, data := e.do("POST", "/v1/orders/"+o.ID+"/certificates", acmeTok, map[string]string{"type": "TAX_HISTORY"})
	c := decode[model.Certificate](t, data)
	for _, st := range []string{"IN_REVIEW", "REJECTED", "REQUESTED"} {
		if code, _, d := e.do("PATCH", "/v1/certificates/"+c.ID+"/status", opsTok, map[string]string{"status": st}); code != 200 {
			t.Fatalf("-> %s: %d %s", st, code, d)
		}
	}
}

// ---------- UTS-GO-103 ----------

func pdfB64() string { return base64.StdEncoding.EncodeToString([]byte("%PDF-1.7\n%fake pdf bytes\n")) }

func (e *env) upload(token, orderID string, body map[string]string) (int, []byte) {
	code, _, data := e.do("POST", "/v1/orders/"+orderID+"/documents", token, body)
	return code, data
}

func TestDocuments_UploadValidation(t *testing.T) {
	e := newEnv(t)
	o := e.createOrder(acmeTok, nil)
	good := map[string]string{"name": "Tax Cert 2025.pdf", "content_type": "application/pdf", "content_base64": pdfB64()}

	if code, _ := e.upload(acmeTok, o.ID, good); code != http.StatusForbidden {
		t.Fatalf("clients must not upload: %d", code)
	}
	cases := map[string]map[string]string{
		"path traversal":   {"name": "../etc/passwd", "content_type": "application/pdf", "content_base64": pdfB64()},
		"bad type":         {"name": "a.exe", "content_type": "application/x-msdownload", "content_base64": pdfB64()},
		"bad base64":       {"name": "a.pdf", "content_type": "application/pdf", "content_base64": "!!!"},
		"content mismatch": {"name": "a.pdf", "content_type": "application/pdf", "content_base64": base64.StdEncoding.EncodeToString([]byte("<html>not a pdf</html>"))},
		"empty":            {"name": "a.pdf", "content_type": "application/pdf", "content_base64": ""},
	}
	for name, body := range cases {
		if code, data := e.upload(opsTok, o.ID, body); code != http.StatusUnprocessableEntity {
			t.Fatalf("%s: got %d %s", name, code, data)
		}
	}
	code, data := e.upload(opsTok, o.ID, good)
	if code != http.StatusCreated {
		t.Fatalf("upload: %d %s", code, data)
	}
	doc := decode[model.Document](t, data)
	raw := decode[map[string]any](t, data)
	if _, leaked := raw["content"]; leaked || doc.SHA256 == "" || doc.Size == 0 {
		t.Fatalf("metadata response wrong/leaky: %s", data)
	}
}

func TestDocuments_OnlyForCompletedOrders(t *testing.T) {
	e := newEnv(t)
	o := e.createOrder(acmeTok, nil)
	e.upload(opsTok, o.ID, map[string]string{"name": "a.pdf", "content_type": "application/pdf", "content_base64": pdfB64()})
	for _, tok := range []string{acmeTok, opsTok} {
		if code, _, _ := e.do("GET", "/v1/orders/"+o.ID+"/documents", tok, nil); code != http.StatusConflict {
			t.Fatalf("list before completion (%s): %d", tok, code)
		}
	}
}

func TestDocuments_SecureDownload(t *testing.T) {
	e := newEnv(t)
	o := e.createOrder(acmeTok, nil)
	_, data := e.upload(opsTok, o.ID, map[string]string{"name": "Tax Cert 2025.pdf", "content_type": "application/pdf", "content_base64": pdfB64()})
	doc := decode[model.Document](t, data)
	e.completeOrder(o.ID)

	code, _, data := e.do("GET", "/v1/orders/"+o.ID+"/documents", acmeTok, nil)
	list := decode[struct {
		Count     int
		Documents []model.Document
	}](t, data)
	if code != 200 || list.Count != 1 || list.Documents[0].ID != doc.ID {
		t.Fatalf("list: %d %s", code, data)
	}

	code, hdr, body := e.do("GET", "/v1/orders/"+o.ID+"/documents/"+doc.ID, acmeTok, nil)
	if code != 200 || !bytes.HasPrefix(body, []byte("%PDF-")) {
		t.Fatalf("download: %d", code)
	}
	if hdr.Get("Content-Type") != "application/pdf" ||
		!strings.HasPrefix(hdr.Get("Content-Disposition"), "attachment") ||
		hdr.Get("X-Content-Type-Options") != "nosniff" ||
		hdr.Get("Cache-Control") != "private, no-store" ||
		hdr.Get("X-Content-SHA256") != doc.SHA256 {
		t.Fatalf("insecure/missing headers: %v", hdr)
	}

	// access is audited without document contents
	acc := e.rec.Find(audit.DocumentAccessed)
	if len(acc) != 1 || acc[0].Actor != "acme-bot" || acc[0].ResourceID != doc.ID {
		t.Fatalf("download audit: %+v", acc)
	}
	if strings.Contains(toJSON(acc[0]), "fake pdf bytes") {
		t.Fatal("document bytes leaked into audit")
	}
}

func TestDocuments_CrossTenantAndCrossOrderDenied(t *testing.T) {
	e := newEnv(t)
	acme := e.createOrder(acmeTok, nil)
	globex := e.createOrder(globexTok, nil)
	_, data := e.upload(opsTok, acme.ID, map[string]string{"name": "a.pdf", "content_type": "application/pdf", "content_base64": pdfB64()})
	doc := decode[model.Document](t, data)
	e.completeOrder(acme.ID)
	e.completeOrder(globex.ID)

	// globex cannot read acme's document via acme's order
	if code, _, _ := e.do("GET", "/v1/orders/"+acme.ID+"/documents/"+doc.ID, globexTok, nil); code != http.StatusNotFound {
		t.Fatalf("cross-tenant download: %d", code)
	}
	// globex cannot read acme's document by pairing it with globex's own order
	if code, _, _ := e.do("GET", "/v1/orders/"+globex.ID+"/documents/"+doc.ID, globexTok, nil); code != http.StatusNotFound {
		t.Fatalf("cross-order download: %d", code)
	}
	if code, _, _ := e.do("GET", "/v1/orders/"+acme.ID+"/documents/doc_missing", acmeTok, nil); code != http.StatusNotFound {
		t.Fatalf("missing doc: %d", code)
	}
	if got := len(e.rec.Find(audit.AccessDenied)); got < 2 {
		t.Fatalf("denials not audited (%d)", got)
	}
	if len(e.rec.Find(audit.DocumentAccessed)) != 0 {
		t.Fatal("no document should have been served")
	}
}
