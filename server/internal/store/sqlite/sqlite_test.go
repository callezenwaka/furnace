package sqlite

import (
	"path/filepath"
	"testing"
	"time"

	"furnace/server/internal/domain"
)

func TestPersistenceRoundTripUsersAndGroups(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "furnace.db")

	first, err := New(dbPath)
	if err != nil {
		t.Fatalf("create sqlite store: %v", err)
	}

	user := domain.User{
		ID:          "usr_1",
		Email:       "persist@example.com",
		DisplayName: "Persisted User",
		Groups:      []string{"engineering"},
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
	}
	if _, err := first.Users().Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	group := domain.Group{
		ID:          "grp_1",
		Name:        "engineering",
		DisplayName: "Engineering",
		MemberIDs:   []string{"usr_1"},
		CreatedAt:   time.Now().UTC().Truncate(time.Microsecond),
	}
	if _, err := first.Groups().Create(group); err != nil {
		t.Fatalf("create group: %v", err)
	}

	if err := first.Close(); err != nil {
		t.Fatalf("close first store: %v", err)
	}

	second, err := New(dbPath)
	if err != nil {
		t.Fatalf("re-open sqlite store: %v", err)
	}
	defer func() { _ = second.Close() }()

	gotUser, err := second.Users().GetByID("usr_1")
	if err != nil {
		t.Fatalf("load persisted user: %v", err)
	}
	if gotUser.Email != user.Email {
		t.Fatalf("user email mismatch, want %q got %q", user.Email, gotUser.Email)
	}

	gotGroup, err := second.Groups().GetByID("grp_1")
	if err != nil {
		t.Fatalf("load persisted group: %v", err)
	}
	if gotGroup.Name != group.Name {
		t.Fatalf("group name mismatch, want %q got %q", group.Name, gotGroup.Name)
	}
}
