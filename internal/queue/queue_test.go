package queue

import (
	"context"
	"testing"
	"time"
)

func TestNewMemoryQueue(t *testing.T) {
	q := NewMemoryQueue(100)
	if q == nil {
		t.Fatal("NewMemoryQueue returned nil")
	}
	if q.maxSize != 100 {
		t.Errorf("Expected maxSize 100, got %d", q.maxSize)
	}
}

func TestEnqueue(t *testing.T) {
	q := NewMemoryQueue(100)

	req := &AuthRequest{
		ID:        "test-1",
		Type:      AuthRequestTypeCIBA,
		ClientID:  "client-1",
		Status:    StatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	err := q.Enqueue(req)
	if err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	if q.Count() != 1 {
		t.Errorf("Expected count 1, got %d", q.Count())
	}
}

func TestEnqueueDuplicate(t *testing.T) {
	q := NewMemoryQueue(100)

	req := &AuthRequest{
		ID:        "test-1",
		Type:      AuthRequestTypeCIBA,
		ClientID:  "client-1",
		Status:    StatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := q.Enqueue(req); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}
	err := q.Enqueue(req)
	if err == nil {
		t.Error("Enqueue should fail for duplicate ID")
	}
}

func TestGetByID(t *testing.T) {
	q := NewMemoryQueue(100)

	req := &AuthRequest{
		ID:        "test-1",
		Type:      AuthRequestTypeCIBA,
		ClientID:  "client-1",
		Status:    StatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := q.Enqueue(req); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	found, err := q.GetByID("test-1")
	if err != nil {
		t.Fatalf("GetByID failed: %v", err)
	}
	if found.ID != "test-1" {
		t.Errorf("Expected ID 'test-1', got %q", found.ID)
	}
}

func TestGetByIDNotFound(t *testing.T) {
	q := NewMemoryQueue(100)

	_, err := q.GetByID("nonexistent")
	if err == nil {
		t.Error("GetByID should fail for nonexistent ID")
	}
}

func TestGetPending(t *testing.T) {
	q := NewMemoryQueue(100)

	req1 := &AuthRequest{
		ID:        "test-1",
		Type:      AuthRequestTypeCIBA,
		ClientID:  "client-1",
		Status:    StatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	req2 := &AuthRequest{
		ID:        "test-2",
		Type:      AuthRequestTypeCIBA,
		ClientID:  "client-2",
		Status:    StatusApproved,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := q.Enqueue(req1); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}
	if err := q.Enqueue(req2); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	pending, err := q.GetPending()
	if err != nil {
		t.Fatalf("GetPending failed: %v", err)
	}

	if len(pending) != 1 {
		t.Errorf("Expected 1 pending request, got %d", len(pending))
	}
	if pending[0].ID != "test-1" {
		t.Errorf("Expected pending ID 'test-1', got %q", pending[0].ID)
	}
}

func TestApprove(t *testing.T) {
	q := NewMemoryQueue(100)

	req := &AuthRequest{
		ID:        "test-1",
		Type:      AuthRequestTypeCIBA,
		ClientID:  "client-1",
		Status:    StatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := q.Enqueue(req); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	err := q.Approve("test-1", "user-1")
	if err != nil {
		t.Fatalf("Approve failed: %v", err)
	}

	found, _ := q.GetByID("test-1")
	if found.Status != StatusApproved {
		t.Errorf("Expected status 'approved', got %q", found.Status)
	}
	if found.UserID != "user-1" {
		t.Errorf("Expected UserID 'user-1', got %q", found.UserID)
	}
}

func TestApproveNotFound(t *testing.T) {
	q := NewMemoryQueue(100)

	err := q.Approve("nonexistent", "user-1")
	if err == nil {
		t.Error("Approve should fail for nonexistent ID")
	}
}

func TestDeny(t *testing.T) {
	q := NewMemoryQueue(100)

	req := &AuthRequest{
		ID:        "test-1",
		Type:      AuthRequestTypeCIBA,
		ClientID:  "client-1",
		Status:    StatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := q.Enqueue(req); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	err := q.Deny("test-1", "User denied")
	if err != nil {
		t.Fatalf("Deny failed: %v", err)
	}

	found, _ := q.GetByID("test-1")
	if found.Status != StatusDenied {
		t.Errorf("Expected status 'denied', got %q", found.Status)
	}
	if found.DenialReason != "User denied" {
		t.Errorf("Expected denial reason 'User denied', got %q", found.DenialReason)
	}
}

func TestDenyNotFound(t *testing.T) {
	q := NewMemoryQueue(100)

	err := q.Deny("nonexistent", "reason")
	if err == nil {
		t.Error("Deny should fail for nonexistent ID")
	}
}

func TestCount(t *testing.T) {
	q := NewMemoryQueue(100)

	if q.Count() != 0 {
		t.Errorf("Expected count 0, got %d", q.Count())
	}

	req1 := &AuthRequest{
		ID:        "test-1",
		Type:      AuthRequestTypeCIBA,
		ClientID:  "client-1",
		Status:    StatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	req2 := &AuthRequest{
		ID:        "test-2",
		Type:      AuthRequestTypeCIBA,
		ClientID:  "client-2",
		Status:    StatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := q.Enqueue(req1); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}
	if err := q.Enqueue(req2); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	if q.Count() != 2 {
		t.Errorf("Expected count 2, got %d", q.Count())
	}
}

func TestCleanup(t *testing.T) {
	q := NewMemoryQueue(100)

	expiredReq := &AuthRequest{
		ID:        "expired-1",
		Type:      AuthRequestTypeCIBA,
		ClientID:  "client-1",
		Status:    StatusPending,
		CreatedAt: time.Now().Add(-10 * time.Minute),
		ExpiresAt: time.Now().Add(-5 * time.Minute),
	}

	validReq := &AuthRequest{
		ID:        "valid-1",
		Type:      AuthRequestTypeCIBA,
		ClientID:  "client-2",
		Status:    StatusPending,
		CreatedAt: time.Now(),
		ExpiresAt: time.Now().Add(5 * time.Minute),
	}

	if err := q.Enqueue(expiredReq); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}
	if err := q.Enqueue(validReq); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	q.cleanup()

	if q.Count() != 1 {
		t.Errorf("Expected count 1 after cleanup, got %d", q.Count())
	}

	_, err := q.GetByID("expired-1")
	if err == nil {
		t.Error("Expired request should be removed")
	}

	_, err = q.GetByID("valid-1")
	if err != nil {
		t.Error("Valid request should still exist")
	}
}

func TestStartCleanup(t *testing.T) {
	q := NewMemoryQueue(100)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go q.StartCleanup(ctx, 100*time.Millisecond)

	expiredReq := &AuthRequest{
		ID:        "expired-1",
		Type:      AuthRequestTypeCIBA,
		ClientID:  "client-1",
		Status:    StatusPending,
		CreatedAt: time.Now().Add(-10 * time.Minute),
		ExpiresAt: time.Now().Add(-5 * time.Minute),
	}

	if err := q.Enqueue(expiredReq); err != nil {
		t.Fatalf("Enqueue failed: %v", err)
	}

	time.Sleep(200 * time.Millisecond)

	if q.Count() != 0 {
		t.Errorf("Expected count 0 after cleanup, got %d", q.Count())
	}
}

func TestPoll(t *testing.T) {
	q := NewMemoryQueue(100)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = q.Enqueue(&AuthRequest{
			ID:        "test-1",
			Type:      AuthRequestTypeCIBA,
			ClientID:  "client-1",
			Status:    StatusPending,
			CreatedAt: time.Now(),
			ExpiresAt: time.Now().Add(5 * time.Minute),
		})
	}()

	ch := q.Poll(ctx, 50*time.Millisecond)

	select {
	case req := <-ch:
		if req.ID != "test-1" {
			t.Errorf("Expected ID 'test-1', got %q", req.ID)
		}
	case <-time.After(2 * time.Second):
		t.Error("Timeout waiting for poll")
	}
}
