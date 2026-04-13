package httpapi

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"authpilot/server/internal/store/memory"
)

// makeJWT builds a minimal unsigned JWT with the given claims (base64url-encoded
// JSON). The signature part is a placeholder — this is a dev tool and no
// verification is performed.
func makeJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	b64 := base64.RawURLEncoding.EncodeToString
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	header := b64([]byte(`{"alg":"RS256","typ":"JWT"}`))
	body := b64(payload)
	return header + "." + body + ".sig"
}

func newDebugRouter(t *testing.T) http.Handler {
	t.Helper()
	return NewRouter(Dependencies{
		Users:    memory.NewUserStore(),
		Groups:   memory.NewGroupStore(),
		Flows:    memory.NewFlowStore(),
		Sessions: memory.NewSessionStore(),
		APIKey:   "test-key",
	})
}

func TestTokenCompare_MissingAuthpilotToken(t *testing.T) {
	r := newDebugRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/token-compare?provider_token=abc", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestTokenCompare_MissingProviderToken(t *testing.T) {
	r := newDebugRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/token-compare?authpilot_token=abc", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
}

func TestTokenCompare_InvalidJWT(t *testing.T) {
	r := newDebugRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/token-compare?authpilot_token=notajwt&provider_token=notajwt", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422, got %d", rr.Code)
	}
}

func TestTokenCompare_IdenticalTokens_NoDiff(t *testing.T) {
	claims := map[string]any{"sub": "u1", "email": "a@b.com"}
	tok := makeJWT(t, claims)

	r := newDebugRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/token-compare?authpilot_token="+tok+"&provider_token="+tok, nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	diffs, ok := resp["differences"].([]any)
	if !ok {
		t.Fatalf("expected differences array, got %T", resp["differences"])
	}
	if len(diffs) != 0 {
		t.Fatalf("expected 0 diffs for identical tokens, got %d", len(diffs))
	}
}

func TestTokenCompare_DifferentClaims_ReturnsDiff(t *testing.T) {
	authpilotClaims := map[string]any{"sub": "u1", "email": "a@b.com", "name": "Alice"}
	// Simulated Azure AD token: email renamed to preferred_username, tid added
	providerClaims := map[string]any{"sub": "u1", "preferred_username": "a@b.com", "name": "Alice", "tid": "common"}

	apTok := makeJWT(t, authpilotClaims)
	pvTok := makeJWT(t, providerClaims)

	r := newDebugRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/token-compare?authpilot_token="+apTok+"&provider_token="+pvTok, nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rr.Code, rr.Body.String())
	}
	var resp map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	diffs, ok := resp["differences"].([]any)
	if !ok {
		t.Fatalf("expected differences array, got %T", resp["differences"])
	}
	// email present in authpilot, missing in provider
	// preferred_username missing in authpilot, present in provider
	// tid missing in authpilot, present in provider
	if len(diffs) == 0 {
		t.Fatal("expected diffs between authpilot and azure tokens")
	}
}

func TestTokenCompare_UnknownFlowID_Returns404(t *testing.T) {
	claims := map[string]any{"sub": "u1"}
	tok := makeJWT(t, claims)

	r := newDebugRouter(t)
	req := httptest.NewRequest(http.MethodGet, "/api/v1/debug/token-compare?authpilot_token="+tok+"&provider_token="+tok+"&flow_id=no-such-flow", nil)
	req.Header.Set("Authorization", "Bearer test-key")
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)

	if rr.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", rr.Code)
	}
}

// diffClaims unit tests

func TestDiffClaims_Empty(t *testing.T) {
	diffs := diffClaims(map[string]any{}, map[string]any{})
	if len(diffs) != 0 {
		t.Fatalf("expected no diffs, got %d", len(diffs))
	}
}

func TestDiffClaims_MissingInProvider(t *testing.T) {
	diffs := diffClaims(map[string]any{"email": "a@b.com"}, map[string]any{})
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Path != "email" {
		t.Fatalf("expected path=email, got %s", diffs[0].Path)
	}
}

func TestDiffClaims_MissingInAuthpilot(t *testing.T) {
	diffs := diffClaims(map[string]any{}, map[string]any{"tid": "common"})
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Path != "tid" {
		t.Fatalf("expected path=tid, got %s", diffs[0].Path)
	}
}

func TestDiffClaims_ValueDiffers(t *testing.T) {
	diffs := diffClaims(map[string]any{"sub": "u1"}, map[string]any{"sub": "u2"})
	if len(diffs) != 1 {
		t.Fatalf("expected 1 diff, got %d", len(diffs))
	}
	if diffs[0].Note != "values differ" {
		t.Fatalf("expected note 'values differ', got %s", diffs[0].Note)
	}
}
