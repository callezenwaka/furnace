package scim_test

// SCIM 2.0 interoperability test — simulates the provisioning sequence an
// external IdP (Okta, Azure AD, Google Workspace) would perform against
// Authpilot's /scim/v2 endpoint.
//
// The sequence mirrors RFC 7644 §3 (SCIM protocol) and the Okta SCIM 2.0
// provisioning profile:
//  1. GET ServiceProviderConfig — discover capabilities
//  2. GET Schemas — enumerate supported schemas
//  3. POST /Users — provision two users
//  4. GET /Users?filter=userName eq "..."  — verify filter-based lookup
//  5. PATCH /Users/{id} op=replace active=false — deactivate a user
//  6. PUT /Users/{id} — full user replace (reconcile)
//  7. POST /Groups — provision a group
//  8. PATCH /Groups/{id} op=add members — add a user to the group
//  9. GET /Groups/{id} — verify member display names are resolved
// 10. PATCH /Groups/{id} op=remove members — remove a user from the group
// 11. DELETE /Users/{id} — deprovision a user
// 12. DELETE /Groups/{id} — deprovision a group
// 13. GET /Users — verify final state (one user remaining, no groups)

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"authpilot/server/internal/scim"
	"authpilot/server/internal/store/memory"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newInteropRouter() http.Handler {
	return scim.NewRouter(scim.RouterDeps{
		Users:  memory.NewUserStore(),
		Groups: memory.NewGroupStore(),
	})
}

type interopClient struct {
	t   *testing.T
	srv *httptest.Server
}

func (c *interopClient) do(method, path string, body any) (int, map[string]any) {
	c.t.Helper()
	var reqBody *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		reqBody = bytes.NewReader(b)
	} else {
		reqBody = bytes.NewReader(nil)
	}
	req, _ := http.NewRequest(method, c.srv.URL+path, reqBody)
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("Accept", "application/scim+json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		c.t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out
}

func (c *interopClient) mustStatus(status int, got int, op string) {
	c.t.Helper()
	if got != status {
		c.t.Fatalf("%s: expected %d, got %d", op, status, got)
	}
}

// ---------------------------------------------------------------------------
// Interoperability sequence
// ---------------------------------------------------------------------------

func TestSCIM_InteropProvisioningSequence(t *testing.T) {
	srv := httptest.NewServer(newInteropRouter())
	t.Cleanup(srv.Close)
	cl := &interopClient{t: t, srv: srv}

	// ── 1. ServiceProviderConfig ─────────────────────────────────────────────
	code, spc := cl.do(http.MethodGet, "/scim/v2/ServiceProviderConfig", nil)
	cl.mustStatus(200, code, "ServiceProviderConfig")
	if spc["patch"] == nil {
		t.Error("ServiceProviderConfig: patch capability missing")
	}
	if spc["filter"] == nil {
		t.Error("ServiceProviderConfig: filter capability missing")
	}
	// Verify content-type advertises SCIM.
	patchCap, _ := spc["patch"].(map[string]any)
	if supported, _ := patchCap["supported"].(bool); !supported {
		t.Error("patch.supported should be true")
	}

	// ── 2. Schemas list ──────────────────────────────────────────────────────
	code, schemas := cl.do(http.MethodGet, "/scim/v2/Schemas", nil)
	cl.mustStatus(200, code, "GET Schemas")
	resources, _ := schemas["Resources"].([]any)
	if len(resources) < 2 {
		t.Errorf("expected at least 2 schemas, got %d", len(resources))
	}

	// ── 3. Provision user Alice ──────────────────────────────────────────────
	code, alice := cl.do(http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":    "alice@example.com",
		"displayName": "Alice Smith",
		"active":      true,
		"emails":      []map[string]any{{"value": "alice@example.com", "primary": true}},
		"phoneNumbers": []map[string]any{{"value": "+15550001111", "primary": true}},
	})
	cl.mustStatus(201, code, "POST /Users alice")
	aliceID, _ := alice["id"].(string)
	if aliceID == "" {
		t.Fatal("POST /Users: alice.id is empty")
	}
	if alice["userName"] != "alice@example.com" {
		t.Errorf("alice userName: %v", alice["userName"])
	}

	// ── Provision user Bob ───────────────────────────────────────────────────
	code, bob := cl.do(http.MethodPost, "/scim/v2/Users", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":    "bob@example.com",
		"displayName": "Bob Jones",
		"active":      true,
		"emails":      []map[string]any{{"value": "bob@example.com", "primary": true}},
	})
	cl.mustStatus(201, code, "POST /Users bob")
	bobID, _ := bob["id"].(string)
	if bobID == "" {
		t.Fatal("POST /Users: bob.id is empty")
	}

	// ── 4. Filter by userName ────────────────────────────────────────────────
	code, list := cl.do(http.MethodGet, `/scim/v2/Users?filter=userName+eq+%22alice%40example.com%22`, nil)
	cl.mustStatus(200, code, "GET /Users?filter=userName eq alice")
	total, _ := list["totalResults"].(float64)
	if total != 1 {
		t.Errorf("filter: totalResults = %v, want 1", total)
	}
	filterResources, _ := list["Resources"].([]any)
	if len(filterResources) != 1 {
		t.Fatalf("filter: got %d resources, want 1", len(filterResources))
	}
	filtered, _ := filterResources[0].(map[string]any)
	if filtered["id"] != aliceID {
		t.Errorf("filter: got id %v, want %v", filtered["id"], aliceID)
	}

	// ── 5. Deactivate Alice (PATCH replace active=false) ─────────────────────
	code, _ = cl.do(http.MethodPatch, "/scim/v2/Users/"+aliceID, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "replace", "path": "active", "value": false},
		},
	})
	cl.mustStatus(200, code, "PATCH /Users alice active=false")

	// Verify deactivation persisted.
	code, aliceGet := cl.do(http.MethodGet, "/scim/v2/Users/"+aliceID, nil)
	cl.mustStatus(200, code, "GET /Users/alice after deactivate")
	if aliceGet["active"] != false {
		t.Errorf("alice.active after deactivate: %v", aliceGet["active"])
	}

	// ── 6. Full replace (PUT) — reconcile all fields ─────────────────────────
	code, alicePut := cl.do(http.MethodPut, "/scim/v2/Users/"+aliceID, map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":    "alice@example.com",
		"displayName": "Alice M. Smith",
		"active":      true,
		"emails":      []map[string]any{{"value": "alice@example.com", "primary": true}},
	})
	cl.mustStatus(200, code, "PUT /Users alice (replace)")
	if alicePut["displayName"] != "Alice M. Smith" {
		t.Errorf("PUT: displayName = %v", alicePut["displayName"])
	}
	if alicePut["active"] != true {
		t.Errorf("PUT: active = %v after re-activate", alicePut["active"])
	}

	// ── 7. Provision a group ─────────────────────────────────────────────────
	code, eng := cl.do(http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas":     []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
		"displayName": "Engineering",
	})
	cl.mustStatus(201, code, "POST /Groups engineering")
	engID, _ := eng["id"].(string)
	if engID == "" {
		t.Fatal("POST /Groups: eng.id is empty")
	}

	// ── 8. Add Alice to Engineering (PATCH add members) ──────────────────────
	code, _ = cl.do(http.MethodPatch, "/scim/v2/Groups/"+engID, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "add", "path": "members", "value": []map[string]any{
				{"value": aliceID},
			}},
		},
	})
	cl.mustStatus(200, code, "PATCH /Groups add alice")

	// ── 9. GET group — verify member display name resolved ───────────────────
	code, engGet := cl.do(http.MethodGet, "/scim/v2/Groups/"+engID, nil)
	cl.mustStatus(200, code, "GET /Groups/eng after add")
	members, _ := engGet["members"].([]any)
	if len(members) != 1 {
		t.Fatalf("group members after add: got %d, want 1", len(members))
	}
	member, _ := members[0].(map[string]any)
	if member["value"] != aliceID {
		t.Errorf("member value: %v, want %v", member["value"], aliceID)
	}
	if member["display"] != "Alice M. Smith" {
		t.Errorf("member display: %v, want Alice M. Smith", member["display"])
	}

	// ── 10. Remove Alice from Engineering (PATCH remove members) ─────────────
	code, _ = cl.do(http.MethodPatch, "/scim/v2/Groups/"+engID, map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "remove", "path": "members", "value": []map[string]any{
				{"value": aliceID},
			}},
		},
	})
	cl.mustStatus(200, code, "PATCH /Groups remove alice")

	code, engAfterRemove := cl.do(http.MethodGet, "/scim/v2/Groups/"+engID, nil)
	cl.mustStatus(200, code, "GET /Groups/eng after remove")
	membersAfter, _ := engAfterRemove["members"].([]any)
	if len(membersAfter) != 0 {
		t.Errorf("group members after remove: got %d, want 0", len(membersAfter))
	}

	// ── 11. Deprovision Bob ───────────────────────────────────────────────────
	code, _ = cl.do(http.MethodDelete, "/scim/v2/Users/"+bobID, nil)
	cl.mustStatus(204, code, "DELETE /Users bob")

	// Verify Bob is gone.
	code, _ = cl.do(http.MethodGet, "/scim/v2/Users/"+bobID, nil)
	cl.mustStatus(404, code, "GET /Users bob after delete")

	// ── 12. Deprovision Engineering group ────────────────────────────────────
	code, _ = cl.do(http.MethodDelete, "/scim/v2/Groups/"+engID, nil)
	cl.mustStatus(204, code, "DELETE /Groups eng")

	// ── 13. Final state: only Alice remains ──────────────────────────────────
	code, finalList := cl.do(http.MethodGet, "/scim/v2/Users", nil)
	cl.mustStatus(200, code, "GET /Users final")
	finalTotal, _ := finalList["totalResults"].(float64)
	if finalTotal != 1 {
		t.Errorf("final totalResults = %v, want 1 (only alice)", finalTotal)
	}
	finalResources, _ := finalList["Resources"].([]any)
	if len(finalResources) != 1 {
		t.Fatalf("final resources: got %d, want 1", len(finalResources))
	}
	finalUser, _ := finalResources[0].(map[string]any)
	if finalUser["id"] != aliceID {
		t.Errorf("final remaining user id: %v, want %v", finalUser["id"], aliceID)
	}

	code, finalGroups := cl.do(http.MethodGet, "/scim/v2/Groups", nil)
	cl.mustStatus(200, code, "GET /Groups final")
	finalGroupTotal, _ := finalGroups["totalResults"].(float64)
	if finalGroupTotal != 0 {
		t.Errorf("final groups totalResults = %v, want 0", finalGroupTotal)
	}

	t.Logf("SCIM interop sequence complete: aliceID=%s", aliceID)
}

// TestSCIM_DuplicateUserName verifies that creating two users with the same
// userName returns a 409 Conflict — required by RFC 7644 §3.3.
func TestSCIM_DuplicateUserName(t *testing.T) {
	srv := httptest.NewServer(newInteropRouter())
	t.Cleanup(srv.Close)
	cl := &interopClient{t: t, srv: srv}

	body := map[string]any{
		"schemas":  []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName": "dup@example.com",
	}
	code, _ := cl.do(http.MethodPost, "/scim/v2/Users", body)
	cl.mustStatus(201, code, "first POST /Users")

	code, resp := cl.do(http.MethodPost, "/scim/v2/Users", body)
	if code != http.StatusConflict {
		t.Errorf("duplicate userName: expected 409, got %d (%v)", code, resp)
	}
}

// TestSCIM_GroupDisplayNameRequired verifies that POST /Groups without
// displayName returns 400 — required by RFC 7644.
func TestSCIM_GroupDisplayNameRequired(t *testing.T) {
	srv := httptest.NewServer(newInteropRouter())
	t.Cleanup(srv.Close)
	cl := &interopClient{t: t, srv: srv}

	code, _ := cl.do(http.MethodPost, "/scim/v2/Groups", map[string]any{
		"schemas": []string{"urn:ietf:params:scim:schemas:core:2.0:Group"},
	})
	if code != http.StatusBadRequest {
		t.Errorf("missing displayName: expected 400, got %d", code)
	}
}

// TestSCIM_SchemaByURN verifies individual schema retrieval — used by IdPs
// to discover attribute definitions before provisioning.
func TestSCIM_SchemaByURN(t *testing.T) {
	srv := httptest.NewServer(newInteropRouter())
	t.Cleanup(srv.Close)
	cl := &interopClient{t: t, srv: srv}

	for _, urn := range []string{
		"urn:ietf:params:scim:schemas:core:2.0:User",
		"urn:ietf:params:scim:schemas:core:2.0:Group",
	} {
		code, schema := cl.do(http.MethodGet, fmt.Sprintf("/scim/v2/Schemas/%s", urn), nil)
		if code != 200 {
			t.Errorf("GET Schemas/%s: expected 200, got %d", urn, code)
			continue
		}
		if schema["id"] != urn {
			t.Errorf("schema id: got %v, want %v", schema["id"], urn)
		}
	}

	// Unknown URN → 404.
	code, _ := cl.do(http.MethodGet, "/scim/v2/Schemas/urn:unknown", nil)
	if code != 404 {
		t.Errorf("unknown schema URN: expected 404, got %d", code)
	}
}
