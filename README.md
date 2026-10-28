# UTS Property-Tax Service (Go)

Go backend for United Tax Services covering JIRA **UTS-GO-101 … UTS-GO-108**.
Standard library only (Go 1.22+, uses the 1.22 `ServeMux` method/path patterns) — no third-party dependencies.

## JIRA → code map

| JIRA | Deliverable | Where |
|---|---|---|
| UTS-GO-101 | REST APIs: create / validate / update / status-track property-tax orders | `internal/api/orders.go`, `internal/model`, `internal/store` |
| UTS-GO-102 | Tax-certificate requests with a defined state machine (`REQUESTED → IN_REVIEW → ISSUED / REJECTED / CANCELLED`) | `internal/api/certificates.go`, `internal/model/model.go` |
| UTS-GO-103 | Secure document retrieval for completed orders (auth, tenant isolation, completed-only, safe headers, SHA-256, audited) | `internal/api/documents.go` |
| UTS-GO-104 | Validation of parcel, property, tax year, jurisdiction, order data (+ stricter pre-processing rules) | `internal/validation/validation.go` |
| UTS-GO-105 | Integration services for title/closing platform and downstream tax system, with an audited dispatcher | `internal/integration/integration.go` |
| UTS-GO-106 | Retry w/ exponential backoff + jitter, per-attempt timeouts, permanent-error short-circuit, circuit breaker | `internal/resilience/resilience.go` |
| UTS-GO-107 | Structured audit logging (order, update, document-access, integration, auth/denied events; secret redaction) | `internal/audit/audit.go` |
| UTS-GO-108 | Automated tests (unit + HTTP-level, run with `-race`) | `*_test.go` in every package |

## Run

```bash
export UTS_API_TOKENS="admin-token-0123456789:alice:admin,ops-token-0123456789ab:olivia:ops,acme-token-0123456789a:acme-bot:client:acme"
# optional integrations
export TITLE_PLATFORM_URL=https://title.example.com   TITLE_PLATFORM_KEY=...
export TAX_SYSTEM_URL=https://taxsys.example.com      TAX_SYSTEM_KEY=...
export AUDIT_LOG_PATH=./audit.log                     # optional dedicated audit stream
go run ./cmd/server
```

Tokens are `token:actor:role[:client_id]`, roles `admin | ops | client` (client tokens need a client_id; tokens ≥ 16 chars).

## Test

```bash
go vet ./... && go test -race -cover ./...
```

## API

All routes except `/healthz` need `Authorization: Bearer <token>`. Errors share one shape:
`{"error":{"code","message","request_id","details"}}`.

| Method & path | Purpose | Who |
|---|---|---|
| `POST /v1/orders` | Create order (422 on validation errors, 409 on duplicate) | client, staff |
| `GET /v1/orders?status=&limit=&offset=` | List (clients see only their own) | all |
| `GET /v1/orders/{id}` | Fetch | owner, staff |
| `PUT /v1/orders/{id}` | Update; body must include current `version` (409 on stale). Editing a VALIDATED order resets it to CREATED | owner, staff |
| `POST /v1/orders/{id}/validate` | Run processing rules; CREATED → VALIDATED (idempotent) | owner, staff |
| `PATCH /v1/orders/{id}/status` | Transition (`IN_PROGRESS`, `COMPLETED`, `FAILED`, `CANCELLED`) | staff; clients may only cancel |
| `GET /v1/orders/{id}/status` | Status, history, certificate summary | owner, staff |
| `POST /v1/orders/{id}/certificates` | Request certificate (`CURRENT_TAX`, `DELINQUENT_TAX`, `TAX_HISTORY`, `PAID_RECEIPT`) | owner, staff |
| `GET /v1/orders/{id}/certificates`, `GET /v1/certificates/{id}` | Read | owner, staff |
| `PATCH /v1/certificates/{id}/status` | Advance certificate state | staff; clients may only cancel |
| `POST /v1/orders/{id}/documents` | Upload (JSON, base64) | staff |
| `GET /v1/orders/{id}/documents` | List metadata (COMPLETED orders only) | owner, staff |
| `GET /v1/orders/{id}/documents/{docID}` | Download (COMPLETED orders only) | owner, staff |

Order state machine: `CREATED → VALIDATED → IN_PROGRESS → COMPLETED`, with `FAILED` (retryable to `IN_PROGRESS`) and `CANCELLED`.

### Example

```bash
curl -s -X POST localhost:8080/v1/orders -H "Authorization: Bearer acme-token-0123456789a" \
  -H 'Content-Type: application/json' -d '{
    "parcel_number":"R-12345.001","property_address":"100 Main St, Bentonville",
    "state":"AR","county":"Benton","jurisdiction":"Benton County Collector",
    "tax_year":2025,"owner_name":"Jane Q. Public"}'
```

## Behaviour worth knowing

- **Integrations run in the background.** Entering `IN_PROGRESS` submits the order to the tax system (idempotency key `submit:<order>:v<version>`); if that fails after all retries the order moves to `FAILED` (history entry by `system`) so staff can retry. Every status change is published to the title platform. Outcomes are audited as `integration.succeeded` / `integration.failed`.
- **Resilience layering:** `Retry( PerAttemptTimeout( Breaker( HTTP call ) ) )`. 5xx/429/408/network errors are retried; other 4xx are permanent; an open circuit fails fast without retrying.
- **Tenant isolation:** a caller who may not see an order gets `404`, never `403`, and the attempt is audited as `access.denied`.
- **Audit:** one JSON line per event with actor, client, request id, resource and outcome. Keys containing `token`, `authorization`, `password`, `secret`, `api_key`, `content` or `ssn` are redacted; document bytes are never logged.

## Production hardening (not included)

- `store.Memory` is for development/tests. Implement `store.Store` on PostgreSQL (the `UpdateOrder(fn)` contract maps to `SELECT … FOR UPDATE` or a version-checked `UPDATE`, and the duplicate-order rule to a partial unique index).
- Move documents to object storage (S3/GCS) with server-side encryption; keep only metadata + checksum in the DB.
- Replace `StaticTokens` with OIDC/JWT validation by implementing `api.Authenticator`.
- Background integration work is in-process; use an outbox table + worker if you need delivery to survive restarts.
- Add rate limiting and TLS termination at the edge.
