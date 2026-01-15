package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Morditux/ratelimiter"
	"github.com/Morditux/ratelimiter/store"
)

// MockStore is a mock implementation of store.Store for testing
type MockStore struct {
	GetFunc    func(key string) (interface{}, bool)
	SetFunc    func(key string, value interface{}, ttl time.Duration) error
	DeleteFunc func(key string) error
	CloseFunc  func() error
}

func (m *MockStore) Get(key string) (interface{}, bool) {
	if m.GetFunc != nil {
		return m.GetFunc(key)
	}
	return nil, false
}

func (m *MockStore) Set(key string, value interface{}, ttl time.Duration) error {
	if m.SetFunc != nil {
		return m.SetFunc(key, value, ttl)
	}
	return nil
}

func (m *MockStore) Delete(key string) error {
	if m.DeleteFunc != nil {
		return m.DeleteFunc(key)
	}
	return nil
}

func (m *MockStore) Close() error {
	if m.CloseFunc != nil {
		return m.CloseFunc()
	}
	return nil
}

func TestRouter_Security_FailClosed(t *testing.T) {
	// Setup a mock store that simulates a full store
	mockStore := &MockStore{
		GetFunc: func(key string) (interface{}, bool) {
			return nil, false
		},
		SetFunc: func(key string, value interface{}, ttl time.Duration) error {
			return store.ErrStoreFull
		},
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("OK"))
	})

	router, err := NewRouter(handler, mockStore, []EndpointConfig{
		{
			Path: "/api/test",
			Config: ratelimiter.Config{
				Rate:   10,
				Window: time.Minute,
			},
		},
	})
	if err != nil {
		t.Fatalf("Failed to create router: %v", err)
	}

	req := httptest.NewRequest("GET", "/api/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	// Now it should return 503
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("Expected status 503 (Fail Closed - Secured), got %d", w.Code)
	}

	// Now check ErrKeyTooLong
	mockStore.SetFunc = func(key string, value interface{}, ttl time.Duration) error {
		return store.ErrKeyTooLong
	}

	w = httptest.NewRecorder()
	router.ServeHTTP(w, req)

	// Now it should return 431
	if w.Code != http.StatusRequestHeaderFieldsTooLarge {
		t.Errorf("Expected status 431 (Fail Closed - Secured), got %d", w.Code)
	}
}
