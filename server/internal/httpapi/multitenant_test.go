package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"authpilot/server/internal/store/memory"
	"authpilot/server/internal/store/tenanted"
	"authpilot/server/internal/tenant"
)

// newMultiTenantRouter builds a router with two isolated tenants.
func newMultiTenantRouter() (http.Handler, string, string) {
	rawUsers := memory.NewUserStore()
	rawGroups := memory.NewGroupStore()
	rawFlows := memory.NewFlowStore()
	rawSessions := memory.NewSessionStore()
	rawAudit := memory.NewAuditStore(0)

	t1Key := "key-tenant1"
	t2Key := "key-tenant2"

	sets := map[string]*tenanted.StoreSet{
		tenant.DefaultTenantID: {
			Users:    tenanted.NewUserStore(rawUsers, tenant.DefaultTenantID),
			Groups:   tenanted.NewGroupStore(rawGroups, tenant.DefaultTenantID),
			Flows:    tenanted.NewFlowStore(rawFlows, tenant.DefaultTenantID),
			Sessions: tenanted.NewSessionStore(rawSessions, tenant.DefaultTenantID),
			Audit:    tenanted.NewAuditStore(rawAudit, tenant.DefaultTenantID),
		},
		"tenant1": {
			Users:    tenanted.NewUserStore(rawUsers, "tenant1"),
			Groups:   tenanted.NewGroupStore(rawGroups, "tenant1"),
			Flows:    tenanted.NewFlowStore(rawFlows, "tenant1"),
			Sessions: tenanted.NewSessionStore(rawSessions, "tenant1"),
			Audit:    tenanted.NewAuditStore(rawAudit, "tenant1"),
		},
		"tenant2": {
			Users:    tenanted.NewUserStore(rawUsers, "tenant2"),
			Groups:   tenanted.NewGroupStore(rawGroups, "tenant2"),
			Flows:    tenanted.NewFlowStore(rawFlows, "tenant2"),
			Sessions: tenanted.NewSessionStore(rawSessions, "tenant2"),
			Audit:    tenanted.NewAuditStore(rawAudit, "tenant2"),
		},
	}
	dispatcher := tenanted.NewDispatcher(sets)

	entries := []TenantEntry{
		{TenantID: "tenant1", APIKey: t1Key, SCIMKey: t1Key},
		{TenantID: "tenant2", APIKey: t2Key, SCIMKey: t2Key},
	}

	router := NewRouter(Dependencies{
		TenantStores:  dispatcher,
		TenantEntries: entries,
	})
	return router, t1Key, t2Key
}

func TestMultiTenant_UserIsolation(t *testing.T) {
	router, t1Key, t2Key := newMultiTenantRouter()

	// Create a user under tenant1.
	body := `{"id":"usr_t1","email":"t1@example.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authpilot-Api-Key", t1Key)
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create under t1: want 201, got %d body=%s", rec.Code, rec.Body.String())
	}

	// tenant1 can retrieve it.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/users/usr_t1", nil)
	req2.Header.Set("X-Authpilot-Api-Key", t1Key)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusOK {
		t.Errorf("t1 get own user: want 200, got %d", rec2.Code)
	}

	// tenant2 cannot retrieve it.
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/users/usr_t1", nil)
	req3.Header.Set("X-Authpilot-Api-Key", t2Key)
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3)
	if rec3.Code != http.StatusNotFound {
		t.Errorf("t2 get t1 user: want 404, got %d body=%s", rec3.Code, rec3.Body.String())
	}
}

func TestMultiTenant_InvalidKey_Returns401(t *testing.T) {
	router, _, _ := newMultiTenantRouter()

	req := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req.Header.Set("X-Authpilot-Api-Key", "bad-key")
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Errorf("want 401, got %d", rec.Code)
	}
}

func TestMultiTenant_ListOnlyOwnUsers(t *testing.T) {
	router, t1Key, t2Key := newMultiTenantRouter()

	for _, id := range []string{"usr_a", "usr_b"} {
		body := `{"id":"` + id + `","email":"` + id + `@t1.com"}`
		req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Authpilot-Api-Key", t1Key)
		router.ServeHTTP(httptest.NewRecorder(), req)
	}

	// tenant2 creates its own user.
	body := `{"id":"usr_c","email":"c@t2.com"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/users", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Authpilot-Api-Key", t2Key)
	router.ServeHTTP(httptest.NewRecorder(), req)

	// tenant1 list should return exactly 2 users.
	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req2.Header.Set("X-Authpilot-Api-Key", t1Key)
	rec2 := httptest.NewRecorder()
	router.ServeHTTP(rec2, req2)

	var users []map[string]any
	decodeJSON(t, rec2, &users)
	if len(users) != 2 {
		t.Errorf("t1 list: want 2 users, got %d", len(users))
	}

	// tenant2 list should return exactly 1 user.
	req3 := httptest.NewRequest(http.MethodGet, "/api/v1/users", nil)
	req3.Header.Set("X-Authpilot-Api-Key", t2Key)
	rec3 := httptest.NewRecorder()
	router.ServeHTTP(rec3, req3)

	var users2 []map[string]any
	decodeJSON(t, rec3, &users2)
	if len(users2) != 1 {
		t.Errorf("t2 list: want 1 user, got %d", len(users2))
	}
}
