// Package store defines the persistence boundary and ships an in-memory implementation.
// Swap Memory for a Postgres-backed type that satisfies Store without touching the API layer.
package store

import (
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"uts-tax-service/internal/model"
)

var (
	ErrNotFound  = errors.New("not found")
	ErrDuplicate = errors.New("an active order already exists for this client, parcel, county and tax year")
)

type OrderFilter struct {
	ClientID string // empty = all clients
	Status   model.OrderStatus
	Limit    int
	Offset   int
}

type Store interface {
	CreateOrder(o model.Order) (model.Order, error)
	GetOrder(id string) (model.Order, error)
	ListOrders(f OrderFilter) []model.Order
	// UpdateOrder applies fn atomically. If fn returns an error nothing is stored.
	UpdateOrder(id string, fn func(*model.Order) error) (model.Order, error)

	CreateCertificate(c model.Certificate) (model.Certificate, error)
	GetCertificate(id string) (model.Certificate, error)
	ListCertificates(orderID string) []model.Certificate
	UpdateCertificate(id string, fn func(*model.Certificate) error) (model.Certificate, error)

	AddDocument(d model.Document) (model.Document, error)
	GetDocument(id string) (model.Document, error)
	ListDocuments(orderID string) []model.Document
}

type Memory struct {
	mu     sync.RWMutex
	orders map[string]model.Order
	certs  map[string]model.Certificate
	docs   map[string]model.Document
}

func NewMemory() *Memory {
	return &Memory{
		orders: map[string]model.Order{},
		certs:  map[string]model.Certificate{},
		docs:   map[string]model.Document{},
	}
}

func cloneOrder(o model.Order) model.Order {
	o.StatusHistory = append([]model.StatusChange(nil), o.StatusHistory...)
	return o
}

func cloneCert(c model.Certificate) model.Certificate {
	c.StatusHistory = append([]model.StatusChange(nil), c.StatusHistory...)
	return c
}

// ---------- orders ----------

func (m *Memory) CreateOrder(o model.Order) (model.Order, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ex := range m.orders {
		if ex.ClientID == o.ClientID && ex.ParcelNumber == o.ParcelNumber && ex.State == o.State &&
			ex.County == o.County && ex.TaxYear == o.TaxYear && ex.Status != model.OrderCancelled {
			return model.Order{}, ErrDuplicate
		}
	}
	m.orders[o.ID] = cloneOrder(o)
	return cloneOrder(o), nil
}

func (m *Memory) GetOrder(id string) (model.Order, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.orders[id]
	if !ok {
		return model.Order{}, ErrNotFound
	}
	return cloneOrder(o), nil
}

func (m *Memory) ListOrders(f OrderFilter) []model.Order {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.Order
	for _, o := range m.orders {
		if f.ClientID != "" && o.ClientID != f.ClientID {
			continue
		}
		if f.Status != "" && o.Status != f.Status {
			continue
		}
		out = append(out, cloneOrder(o))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.Before(out[j].CreatedAt)
	})
	if f.Offset > 0 {
		if f.Offset >= len(out) {
			return nil
		}
		out = out[f.Offset:]
	}
	if f.Limit > 0 && f.Limit < len(out) {
		out = out[:f.Limit]
	}
	return out
}

func (m *Memory) UpdateOrder(id string, fn func(*model.Order) error) (model.Order, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.orders[id]
	if !ok {
		return model.Order{}, ErrNotFound
	}
	work := cloneOrder(cur)
	if err := fn(&work); err != nil {
		return model.Order{}, err
	}
	work.Version = cur.Version + 1
	work.UpdatedAt = time.Now().UTC()
	m.orders[id] = work
	return cloneOrder(work), nil
}

// ---------- certificates ----------

func (m *Memory) CreateCertificate(c model.Certificate) (model.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.orders[c.OrderID]; !ok {
		return model.Certificate{}, fmt.Errorf("order %s: %w", c.OrderID, ErrNotFound)
	}
	m.certs[c.ID] = cloneCert(c)
	return cloneCert(c), nil
}

func (m *Memory) GetCertificate(id string) (model.Certificate, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	c, ok := m.certs[id]
	if !ok {
		return model.Certificate{}, ErrNotFound
	}
	return cloneCert(c), nil
}

func (m *Memory) ListCertificates(orderID string) []model.Certificate {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.Certificate
	for _, c := range m.certs {
		if c.OrderID == orderID {
			out = append(out, cloneCert(c))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt) || (out[i].CreatedAt.Equal(out[j].CreatedAt) && out[i].ID < out[j].ID)
	})
	return out
}

func (m *Memory) UpdateCertificate(id string, fn func(*model.Certificate) error) (model.Certificate, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	cur, ok := m.certs[id]
	if !ok {
		return model.Certificate{}, ErrNotFound
	}
	work := cloneCert(cur)
	if err := fn(&work); err != nil {
		return model.Certificate{}, err
	}
	work.Version = cur.Version + 1
	work.UpdatedAt = time.Now().UTC()
	m.certs[id] = work
	return cloneCert(work), nil
}

// ---------- documents ----------

func (m *Memory) AddDocument(d model.Document) (model.Document, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.orders[d.OrderID]; !ok {
		return model.Document{}, fmt.Errorf("order %s: %w", d.OrderID, ErrNotFound)
	}
	m.docs[d.ID] = d
	return d, nil
}

func (m *Memory) GetDocument(id string) (model.Document, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.docs[id]
	if !ok {
		return model.Document{}, ErrNotFound
	}
	return d, nil
}

func (m *Memory) ListDocuments(orderID string) []model.Document {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []model.Document
	for _, d := range m.docs {
		if d.OrderID == orderID {
			d.Content = nil // metadata only
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.Before(out[j].CreatedAt) || (out[i].CreatedAt.Equal(out[j].CreatedAt) && out[i].ID < out[j].ID)
	})
	return out
}
