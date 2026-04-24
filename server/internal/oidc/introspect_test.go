package oidc_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/oidc"
)

// mintToken is a test helper that issues a real signed token via MintForUser.
func mintToken(t *testing.T, issuer *oidc.Issuer, user domain.User, expiresIn int) string {
	t.Helper()
	tok, err := issuer.MintForUser(user, "test-client", []string{"openid", "email"}, expiresIn)
	if err != nil {
		t.Fatalf("MintForUser: %v", err)
	}
	return tok.AccessToken
}

func newIntrospectDeps(t *testing.T) (oidc.RouterDeps, *oidc.Issuer, domain.User) {
	t.Helper()
	dep := newTestDeps(t)
	user := domain.User{
		ID:          "usr_introspect",
		Email:       "dana@example.com",
		DisplayName: "Dana",
		Groups:      []string{"qa"},
	}
	if _, err := dep.Users.Create(user); err != nil {
		t.Fatalf("create user: %v", err)
	}
	return dep, dep.Issuer, user
}

func introspectPost(t *testing.T, srv *httptest.Server, token string) map[string]any {
	t.Helper()
	form := url.Values{}
	form.Set("token", token)
	resp, err := http.PostForm(srv.URL+"/oauth2/introspect", form)
	if err != nil {
		t.Fatalf("POST introspect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	return body
}

// ---------------------------------------------------------------------------

func TestIntrospect_ActiveToken(t *testing.T) {
	dep, issuer, user := newIntrospectDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	t.Cleanup(srv.Close)

	token := mintToken(t, issuer, user, 3600)
	body := introspectPost(t, srv, token)

	if body["active"] != true {
		t.Errorf("expected active=true, got %v", body["active"])
	}
	if body["sub"] != "usr_introspect" {
		t.Errorf("sub: got %v", body["sub"])
	}
	if body["email"] != "dana@example.com" {
		t.Errorf("email: got %v", body["email"])
	}
	if body["username"] != "dana@example.com" {
		t.Errorf("username: got %v", body["username"])
	}
	groups, _ := body["groups"].([]any)
	if len(groups) == 0 || groups[0] != "qa" {
		t.Errorf("groups: got %v", body["groups"])
	}
	if body["client_id"] != "test-client" {
		t.Errorf("client_id: got %v", body["client_id"])
	}
	if body["exp"] == nil {
		t.Error("exp should be present")
	}
}

func TestIntrospect_ExpiredToken(t *testing.T) {
	dep, _, user := newIntrospectDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	t.Cleanup(srv.Close)

	// Build an issuer with a negative TTL so the token is already expired.
	expiredIssuer := oidc.NewIssuer(dep.KeyMgr, oidc.TokenConfig{
		AccessTokenTTL:  -1 * time.Second,
		IDTokenTTL:      -1 * time.Second,
		RefreshTokenTTL: 24 * time.Hour,
	}, srv.URL)
	token := mintToken(t, expiredIssuer, user, 0) // 0 → use issuer's TTL (−1s)
	body := introspectPost(t, srv, token)

	if body["active"] != false {
		t.Errorf("expected active=false for expired token, got %v", body["active"])
	}
	if len(body) != 1 {
		t.Errorf("inactive response should only have 'active' key, got %v", body)
	}
}

func TestIntrospect_InvalidToken(t *testing.T) {
	dep, _, _ := newIntrospectDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	t.Cleanup(srv.Close)

	body := introspectPost(t, srv, "not.a.jwt")

	if body["active"] != false {
		t.Errorf("expected active=false for garbage token, got %v", body["active"])
	}
}

func TestIntrospect_EmptyToken(t *testing.T) {
	dep, _, _ := newIntrospectDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	t.Cleanup(srv.Close)

	body := introspectPost(t, srv, "")

	if body["active"] != false {
		t.Errorf("expected active=false for empty token, got %v", body["active"])
	}
}

func TestIntrospect_WrongKeyToken(t *testing.T) {
	// Token signed by a different key manager should be inactive.
	dep, _, user := newIntrospectDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	t.Cleanup(srv.Close)

	otherKM, err := oidc.NewKeyManager()
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	otherIssuer := oidc.NewIssuer(otherKM, oidc.TokenConfig{
		AccessTokenTTL:  time.Hour,
		IDTokenTTL:      time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	}, srv.URL)
	token := mintToken(t, otherIssuer, user, 3600)

	body := introspectPost(t, srv, token)

	if body["active"] != false {
		t.Errorf("expected active=false for foreign-key token, got %v", body["active"])
	}
}

func TestIntrospect_InDiscovery(t *testing.T) {
	dep := newTestDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/.well-known/openid-configuration")
	if err != nil {
		t.Fatalf("GET discovery: %v", err)
	}
	defer resp.Body.Close()

	var doc map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		t.Fatalf("decode discovery: %v", err)
	}
	if doc["introspection_endpoint"] == nil {
		t.Error("discovery missing introspection_endpoint")
	}
	endpoint, _ := doc["introspection_endpoint"].(string)
	if !strings.HasSuffix(endpoint, "/oauth2/introspect") {
		t.Errorf("introspection_endpoint should end with /oauth2/introspect, got %q", endpoint)
	}
}

func TestIntrospect_UserStoreLookup_DeletedUser(t *testing.T) {
	// Token for a user that was deleted after issuance — sub is still returned
	// but user-enriched fields (email, groups) are absent.
	dep, issuer, user := newIntrospectDeps(t)
	srv := httptest.NewServer(oidc.NewRouter(dep))
	t.Cleanup(srv.Close)

	token := mintToken(t, issuer, user, 3600)

	// Delete the user from the store.
	if err := dep.Users.Delete(user.ID); err != nil {
		t.Fatalf("delete user: %v", err)
	}

	body := introspectPost(t, srv, token)

	// Token is still cryptographically valid → active must be true.
	if body["active"] != true {
		t.Errorf("expected active=true (valid JWT), got %v", body["active"])
	}
	// But user-enriched fields should be absent.
	if body["email"] != nil {
		t.Errorf("email should be absent for deleted user, got %v", body["email"])
	}
	// sub from the JWT payload should still be present.
	if body["sub"] != "usr_introspect" {
		t.Errorf("sub should still be present from JWT, got %v", body["sub"])
	}
}
