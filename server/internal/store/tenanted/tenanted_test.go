package tenanted

import (
	"context"
	"testing"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
	"furnace/server/internal/store/memory"
	"furnace/server/internal/tenant"
)

// ---- UserStore ----

func TestUserStore_Isolation(t *testing.T) {
	inner := memory.NewUserStore()
	t1 := NewUserStore(inner, "t1")
	t2 := NewUserStore(inner, "t2")

	if _, err := t1.Create(domain.User{ID: "usr_a", Email: "a@t1.com"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// t2 cannot see t1's user.
	if _, err := t2.GetByID("usr_a"); err == nil {
		t.Error("t2 should not find t1's user")
	}

	// t1 can see its own user with original ID.
	u, err := t1.GetByID("usr_a")
	if err != nil {
		t.Fatalf("t1 GetByID: %v", err)
	}
	if u.ID != "usr_a" {
		t.Errorf("ID should be stripped, got %q", u.ID)
	}

	// t1 List returns only t1's users.
	list, _ := t1.List()
	if len(list) != 1 || list[0].ID != "usr_a" {
		t.Errorf("t1 list: want [usr_a], got %v", list)
	}

	// t2 List returns nothing.
	list2, _ := t2.List()
	if len(list2) != 0 {
		t.Errorf("t2 list: want empty, got %v", list2)
	}
}

func TestUserStore_UpdateDelete(t *testing.T) {
	inner := memory.NewUserStore()
	s := NewUserStore(inner, "t1")

	if _, err := s.Create(domain.User{ID: "usr_b", Email: "b@t1.com"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	updated, err := s.Update(domain.User{ID: "usr_b", Email: "b2@t1.com"})
	if err != nil {
		t.Fatalf("update: %v", err)
	}
	if updated.ID != "usr_b" {
		t.Errorf("updated ID should be stripped, got %q", updated.ID)
	}

	if err := s.Delete("usr_b"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if _, err := s.GetByID("usr_b"); err == nil {
		t.Error("expected not found after delete")
	}
}

// ---- GroupStore ----

func TestGroupStore_Isolation(t *testing.T) {
	inner := memory.NewGroupStore()
	t1 := NewGroupStore(inner, "t1")
	t2 := NewGroupStore(inner, "t2")

	if _, err := t1.Create(domain.Group{ID: "grp_a", Name: "admins"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := t2.GetByID("grp_a"); err == nil {
		t.Error("t2 should not find t1's group")
	}

	g, err := t1.GetByID("grp_a")
	if err != nil {
		t.Fatalf("t1 GetByID: %v", err)
	}
	if g.ID != "grp_a" {
		t.Errorf("ID should be stripped, got %q", g.ID)
	}
}

// ---- FlowStore ----

func TestFlowStore_Isolation(t *testing.T) {
	inner := memory.NewFlowStore()
	t1 := NewFlowStore(inner, "t1")
	t2 := NewFlowStore(inner, "t2")

	if _, err := t1.Create(domain.Flow{ID: "flow_a", State: "created"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := t2.GetByID("flow_a"); err == nil {
		t.Error("t2 should not find t1's flow")
	}

	f, err := t1.GetByID("flow_a")
	if err != nil {
		t.Fatalf("t1 GetByID: %v", err)
	}
	if f.ID != "flow_a" {
		t.Errorf("ID should be stripped, got %q", f.ID)
	}
}

// ---- SessionStore ----

func TestSessionStore_Isolation(t *testing.T) {
	inner := memory.NewSessionStore()
	t1 := NewSessionStore(inner, "t1")
	t2 := NewSessionStore(inner, "t2")

	if _, err := t1.Create(domain.Session{ID: "sess_a", UserID: "usr_a"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := t2.GetByID("sess_a"); err == nil {
		t.Error("t2 should not find t1's session")
	}

	sess, err := t1.GetByID("sess_a")
	if err != nil {
		t.Fatalf("t1 GetByID: %v", err)
	}
	if sess.ID != "sess_a" {
		t.Errorf("ID should be stripped, got %q", sess.ID)
	}
}

func TestSessionStore_GetByRefreshToken_Isolation(t *testing.T) {
	inner := memory.NewSessionStore()
	t1 := NewSessionStore(inner, "t1")
	t2 := NewSessionStore(inner, "t2")

	if _, err := t1.Create(domain.Session{ID: "sess_rt", UserID: "usr_a", RefreshToken: "tok_abc"}); err != nil {
		t.Fatalf("create: %v", err)
	}

	// t1 can find by refresh token.
	sess, err := t1.GetByRefreshToken("tok_abc")
	if err != nil {
		t.Fatalf("t1 GetByRefreshToken: %v", err)
	}
	if sess.ID != "sess_rt" {
		t.Errorf("ID should be stripped, got %q", sess.ID)
	}

	// t2 cannot see t1's session via refresh token.
	if _, err := t2.GetByRefreshToken("tok_abc"); err == nil {
		t.Error("t2 should not find t1's session by refresh token")
	}
}

// ---- AuditStore ----

func TestAuditStore_Isolation(t *testing.T) {
	inner := memory.NewAuditStore(0)
	t1 := NewAuditStore(inner, "t1")
	t2 := NewAuditStore(inner, "t2")

	t1.Append(domain.AuditEvent{ID: "aud_1", EventType: "user.created", Actor: "system"})
	t2.Append(domain.AuditEvent{ID: "aud_2", EventType: "user.created", Actor: "system"})

	t1Events := t1.List(store.AuditFilter{})
	if len(t1Events) != 1 || t1Events[0].ID != "aud_1" {
		t.Errorf("t1 audit: want [aud_1], got %v", t1Events)
	}

	t2Events := t2.List(store.AuditFilter{})
	if len(t2Events) != 1 || t2Events[0].ID != "aud_2" {
		t.Errorf("t2 audit: want [aud_2], got %v", t2Events)
	}
}

// ---- Dispatcher ----

func TestDispatcher_ForContext(t *testing.T) {
	inner := memory.NewUserStore()
	sets := map[string]*StoreSet{
		tenant.DefaultTenantID: {Users: NewUserStore(inner, tenant.DefaultTenantID)},
		"acme":                 {Users: NewUserStore(inner, "acme")},
	}
	d := NewDispatcher(sets)

	// No tenant on context → default.
	s := d.ForContext(context.Background())
	if s != sets[tenant.DefaultTenantID] {
		t.Error("expected default store set for empty context")
	}

	// Known tenant.
	ctx := tenant.WithTenant(context.Background(), "acme")
	s = d.ForContext(ctx)
	if s != sets["acme"] {
		t.Error("expected acme store set")
	}

	// Unknown tenant falls back to default.
	ctx = tenant.WithTenant(context.Background(), "unknown")
	s = d.ForContext(ctx)
	if s != sets[tenant.DefaultTenantID] {
		t.Error("expected default store set for unknown tenant")
	}
}
