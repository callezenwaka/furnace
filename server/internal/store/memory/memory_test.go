package memory

import (
	"testing"
	"time"

	"authpilot/server/internal/domain"
)

func TestUserCRUD(t *testing.T) {
	s := NewUserStore()
	now := time.Now().UTC()

	created, err := s.Create(domain.User{ID: "usr_1", Email: "a@example.com", CreatedAt: now})
	if err != nil {
		t.Fatalf("create user: %v", err)
	}
	if created.ID != "usr_1" {
		t.Fatalf("unexpected user id: %s", created.ID)
	}

	got, err := s.GetByID("usr_1")
	if err != nil {
		t.Fatalf("get user: %v", err)
	}
	if got.Email != "a@example.com" {
		t.Fatalf("unexpected email: %s", got.Email)
	}

	got.Email = "updated@example.com"
	if _, err := s.Update(got); err != nil {
		t.Fatalf("update user: %v", err)
	}

	list, err := s.List()
	if err != nil {
		t.Fatalf("list users: %v", err)
	}
	if len(list) != 1 {
		t.Fatalf("unexpected user count: %d", len(list))
	}

	if err := s.Delete("usr_1"); err != nil {
		t.Fatalf("delete user: %v", err)
	}
}

func TestFlowCleanup(t *testing.T) {
	s := NewFlowStore()
	now := time.Now().UTC()

	_, _ = s.Create(domain.Flow{ID: "flow_old", ExpiresAt: now.Add(-time.Minute)})
	_, _ = s.Create(domain.Flow{ID: "flow_new", ExpiresAt: now.Add(time.Minute)})

	removed, err := s.DeleteExpired(now)
	if err != nil {
		t.Fatalf("cleanup flows: %v", err)
	}
	if removed != 1 {
		t.Fatalf("expected 1 removed flow, got %d", removed)
	}
}
