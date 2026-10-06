package queue

import (
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/redis/go-redis/v9"
)

func TestRedisQueueApproveOnceAndExpire(t *testing.T) {
	srv := miniredis.RunT(t)
	rdb := redis.NewClient(&redis.Options{Addr: srv.Addr()})
	t.Cleanup(func() { _ = rdb.Close() })
	q := NewRedis(rdb, "oauth", 2)

	first := &AuthRequest{
		ID: "a", Type: AuthRequestTypeCIBA, ClientID: "app", Status: StatusPending,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute),
	}
	if err := q.Enqueue(first); err != nil {
		t.Fatal(err)
	}
	if err := q.Enqueue(first); err == nil {
		t.Fatal("expected duplicate enqueue to fail")
	}
	second := *first
	second.ID = "b"
	if err := q.Enqueue(&second); err != nil {
		t.Fatal(err)
	}
	third := *first
	third.ID = "c"
	if err := q.Enqueue(&third); err == nil {
		t.Fatal("expected a full queue")
	}
	if err := q.Approve("a", "user-1"); err != nil {
		t.Fatal(err)
	}
	if err := q.Approve("a", "user-2"); err == nil {
		t.Fatal("expected the second approve to fail")
	}
	got, err := q.GetByID("a")
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != StatusApproved || got.UserID != "user-1" {
		t.Fatalf("approved request = %+v", got)
	}
	if err := q.Deny("b", "no"); err != nil {
		t.Fatal(err)
	}
	denied, err := q.GetByID("b")
	if err != nil || denied.Status != StatusDenied || denied.DenialReason != "no" {
		t.Fatalf("denied = %+v err=%v", denied, err)
	}

	short := &AuthRequest{
		ID: "soon", Type: AuthRequestTypeDevice, ClientID: "app", Status: StatusPending,
		CreatedAt: time.Now(), ExpiresAt: time.Now().Add(30 * time.Second),
	}
	q.maxPending = 10
	if err := q.Enqueue(short); err != nil {
		t.Fatal(err)
	}
	srv.FastForward(time.Minute)
	if _, err := q.GetByID("soon"); err == nil {
		t.Fatal("expected the expired request to disappear")
	}
}
