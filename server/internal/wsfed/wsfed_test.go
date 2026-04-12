package wsfed

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"authpilot/server/internal/domain"
	"authpilot/server/internal/saml"
	"authpilot/server/internal/store/memory"
)

func newTestDeps(t *testing.T) RouterDeps {
	t.Helper()
	cm, err := saml.NewCertManager()
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	return RouterDeps{
		Users:      memory.NewUserStore(),
		Sessions:   memory.NewSessionStore(),
		CertMgr:    cm,
		EntityID:   "http://localhost:8026",
		IssuerURL:  "http://localhost:8026/wsfed",
		LoginURL:   "http://localhost:8025/login",
		SessionTTL: 1 * time.Hour,
	}
}

func doWsFed(r http.Handler, method, path string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)
	return rec
}

// --- Federation metadata ---

func TestFederationMetadata_Status(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)
	rec := doWsFed(r, http.MethodGet, "/federationmetadata/2007-06/federationmetadata.xml")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
}

func TestFederationMetadata_ContentType(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)
	rec := doWsFed(r, http.MethodGet, "/federationmetadata/2007-06/federationmetadata.xml")
	ct := rec.Header().Get("Content-Type")
	if !strings.Contains(ct, "application/xml") {
		t.Errorf("Content-Type = %q, want application/xml", ct)
	}
}

func TestFederationMetadata_ContainsEntityID(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)
	rec := doWsFed(r, http.MethodGet, "/federationmetadata/2007-06/federationmetadata.xml")
	body := rec.Body.String()
	if !strings.Contains(body, dep.EntityID) {
		t.Errorf("metadata does not contain entityID %q", dep.EntityID)
	}
	if !strings.Contains(body, dep.IssuerURL) {
		t.Errorf("metadata does not contain issuer URL %q", dep.IssuerURL)
	}
	if !strings.Contains(body, "X509Certificate") {
		t.Error("metadata does not contain X509Certificate")
	}
}

// --- Passive requestor endpoint ---

func TestWsFed_NoWa_InfoPage(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)
	rec := doWsFed(r, http.MethodGet, "/wsfed")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), dep.EntityID) {
		t.Error("info page does not mention EntityID")
	}
}

func TestWsFed_SignIn_MissingWtrealm(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)
	rec := doWsFed(r, http.MethodGet, "/wsfed?wa=wsignin1.0")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestWsFed_SignIn_RedirectsToLogin(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)
	rec := doWsFed(r, http.MethodGet, "/wsfed?wa=wsignin1.0&wtrealm=https://myapp.example.com/")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	loc := rec.Header().Get("Location")
	if !strings.Contains(loc, dep.LoginURL) {
		t.Errorf("redirect location %q does not contain login URL", loc)
	}
}

func TestWsFed_SignOut_NoWreply(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)
	rec := doWsFed(r, http.MethodGet, "/wsfed?wa=wsignout1.0")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "Signed Out") {
		t.Error("expected sign-out confirmation page")
	}
}

func TestWsFed_SignOut_WithWreply(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)
	rec := doWsFed(r, http.MethodGet, "/wsfed?wa=wsignout1.0&wreply=https://myapp.example.com/signout-callback")
	if rec.Code != http.StatusFound {
		t.Fatalf("status = %d, want 302", rec.Code)
	}
	if rec.Header().Get("Location") != "https://myapp.example.com/signout-callback" {
		t.Errorf("redirect = %q", rec.Header().Get("Location"))
	}
}

func TestWsFed_UnknownWa(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)
	rec := doWsFed(r, http.MethodGet, "/wsfed?wa=unknown")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

// --- Token building ---

func TestBuildWSTrustToken(t *testing.T) {
	cm, err := saml.NewCertManager()
	if err != nil {
		t.Fatalf("NewCertManager: %v", err)
	}
	user := domain.User{
		ID:          "u1",
		Email:       "alice@example.com",
		DisplayName: "Alice Smith",
	}
	token, err := buildWSTrustToken(user, "http://localhost:8026", "https://myapp.example.com/", cm)
	if err != nil {
		t.Fatalf("buildWSTrustToken: %v", err)
	}
	if !strings.Contains(token, "RequestSecurityTokenResponse") {
		t.Error("expected RequestSecurityTokenResponse in token")
	}
	if !strings.Contains(token, "alice@example.com") {
		t.Error("expected user email in token")
	}
	if !strings.Contains(token, "ds:Signature") {
		t.Error("expected XML signature in token")
	}
	if !strings.Contains(token, "saml:Assertion") {
		t.Error("expected saml:Assertion in token")
	}
}

func TestCompleteSignIn_NoSession(t *testing.T) {
	dep := newTestDeps(t)
	r := NewRouter(dep)
	// Simulate callback with a flow ID that has no session.
	rec := doWsFed(r, http.MethodGet,
		"/wsfed?wa=wsignin1.0&wtrealm=https://myapp/&wreply=https://myapp/cb&wsfed_flow_id=nonexistent")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400", rec.Code)
	}
}

func TestCompleteSignIn_WithSession(t *testing.T) {
	dep := newTestDeps(t)

	// Seed a user and session.
	user, _ := dep.Users.Create(domain.User{
		ID:          "u1",
		Email:       "alice@example.com",
		DisplayName: "Alice",
	})
	_, _ = dep.Sessions.Create(domain.Session{
		ID:        "sess1",
		UserID:    user.ID,
		FlowID:    "flow_wsfed_test",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	})

	r := NewRouter(dep)
	rec := doWsFed(r, http.MethodGet,
		"/wsfed?wa=wsignin1.0&wtrealm=https://myapp/&wreply=https://myapp/cb&wsfed_flow_id=flow_wsfed_test")
	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body: %s", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	if !strings.Contains(body, `name="wresult"`) {
		t.Error("expected wresult field in POST form")
	}
	if !strings.Contains(body, "wsignin1.0") {
		t.Error("expected wa=wsignin1.0 in POST form")
	}
}
