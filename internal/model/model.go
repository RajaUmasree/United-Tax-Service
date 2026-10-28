// Package model holds the domain types shared by every layer of the UTS tax service.
package model

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// NewID returns a collision-resistant, URL-safe identifier such as "ord_9f2c1a7b3d4e5f60".
func NewID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// ---------- Orders (UTS-GO-101) ----------

type OrderStatus string

const (
	OrderCreated    OrderStatus = "CREATED"
	OrderValidated  OrderStatus = "VALIDATED"
	OrderInProgress OrderStatus = "IN_PROGRESS"
	OrderCompleted  OrderStatus = "COMPLETED"
	OrderFailed     OrderStatus = "FAILED"
	OrderCancelled  OrderStatus = "CANCELLED"
)

var orderTransitions = map[OrderStatus][]OrderStatus{
	OrderCreated:    {OrderValidated, OrderCancelled},
	OrderValidated:  {OrderInProgress, OrderCancelled},
	OrderInProgress: {OrderCompleted, OrderFailed, OrderCancelled},
	OrderFailed:     {OrderInProgress, OrderCancelled}, // failed orders may be retried
}

func (s OrderStatus) Valid() bool {
	switch s {
	case OrderCreated, OrderValidated, OrderInProgress, OrderCompleted, OrderFailed, OrderCancelled:
		return true
	}
	return false
}

func (s OrderStatus) CanTransitionTo(next OrderStatus) bool {
	for _, n := range orderTransitions[s] {
		if n == next {
			return true
		}
	}
	return false
}

// StatusChange is one entry in an order's or certificate's status history.
type StatusChange struct {
	From   string    `json:"from,omitempty"`
	To     string    `json:"to"`
	At     time.Time `json:"at"`
	By     string    `json:"by"`
	Reason string    `json:"reason,omitempty"`
}

type Order struct {
	ID              string         `json:"id"`
	ClientID        string         `json:"client_id"`
	ParcelNumber    string         `json:"parcel_number"`
	PropertyAddress string         `json:"property_address"`
	State           string         `json:"state"`
	County          string         `json:"county"`
	Jurisdiction    string         `json:"jurisdiction"`
	TaxYear         int            `json:"tax_year"`
	OwnerName       string         `json:"owner_name,omitempty"`
	Status          OrderStatus    `json:"status"`
	ExternalRef     string         `json:"external_ref,omitempty"` // reference returned by the downstream tax system
	Version         int            `json:"version"`                // optimistic-concurrency token
	CreatedBy       string         `json:"created_by"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	StatusHistory   []StatusChange `json:"status_history,omitempty"`
}

// ---------- Tax certificates (UTS-GO-102) ----------

type CertificateStatus string

const (
	CertRequested CertificateStatus = "REQUESTED"
	CertInReview  CertificateStatus = "IN_REVIEW"
	CertIssued    CertificateStatus = "ISSUED"
	CertRejected  CertificateStatus = "REJECTED"
	CertCancelled CertificateStatus = "CANCELLED"
)

var certTransitions = map[CertificateStatus][]CertificateStatus{
	CertRequested: {CertInReview, CertCancelled},
	CertInReview:  {CertIssued, CertRejected, CertCancelled},
	CertRejected:  {CertRequested}, // resubmission after correction
}

func (s CertificateStatus) Valid() bool {
	switch s {
	case CertRequested, CertInReview, CertIssued, CertRejected, CertCancelled:
		return true
	}
	return false
}

func (s CertificateStatus) CanTransitionTo(next CertificateStatus) bool {
	for _, n := range certTransitions[s] {
		if n == next {
			return true
		}
	}
	return false
}

type Certificate struct {
	ID            string            `json:"id"`
	OrderID       string            `json:"order_id"`
	Type          string            `json:"type"`
	Status        CertificateStatus `json:"status"`
	Notes         string            `json:"notes,omitempty"`
	RequestedBy   string            `json:"requested_by"`
	Version       int               `json:"version"`
	CreatedAt     time.Time         `json:"created_at"`
	UpdatedAt     time.Time         `json:"updated_at"`
	StatusHistory []StatusChange    `json:"status_history,omitempty"`
}

// ---------- Documents (UTS-GO-103) ----------

type Document struct {
	ID          string    `json:"id"`
	OrderID     string    `json:"order_id"`
	Name        string    `json:"name"`
	ContentType string    `json:"content_type"`
	Size        int       `json:"size"`
	SHA256      string    `json:"sha256"`
	UploadedBy  string    `json:"uploaded_by"`
	CreatedAt   time.Time `json:"created_at"`
	Content     []byte    `json:"-"` // never serialised in metadata responses
}
