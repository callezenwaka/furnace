package personality

import (
	"testing"
)

func TestApply_DefaultPassesThrough(t *testing.T) {
	claims := map[string]any{"sub": "u1", "email": "a@b.com", "name": "Alice"}
	out := Default.Apply(claims)
	if out["email"] != "a@b.com" {
		t.Fatalf("expected email unchanged, got %v", out["email"])
	}
	if out["name"] != "Alice" {
		t.Fatalf("expected name unchanged, got %v", out["name"])
	}
}

func TestApply_AzureAD_RemapsEmail(t *testing.T) {
	claims := map[string]any{"sub": "u1", "email": "a@b.com", "name": "Alice"}
	out := AzureAD.Apply(claims)
	if _, ok := out["email"]; ok {
		t.Fatal("email key should be remapped to preferred_username")
	}
	if out["preferred_username"] != "a@b.com" {
		t.Fatalf("expected preferred_username=a@b.com, got %v", out["preferred_username"])
	}
}

func TestApply_AzureAD_AddsExtraClaims(t *testing.T) {
	claims := map[string]any{"sub": "u1", "email": "a@b.com"}
	out := AzureAD.Apply(claims)
	if out["tid"] != "common" {
		t.Fatalf("expected tid=common, got %v", out["tid"])
	}
	if out["ver"] != "2.0" {
		t.Fatalf("expected ver=2.0, got %v", out["ver"])
	}
}

func TestApply_ExtraClaimsDoNotOverwriteExisting(t *testing.T) {
	claims := map[string]any{"sub": "u1", "tid": "my-tenant"}
	out := AzureAD.Apply(claims)
	if out["tid"] != "my-tenant" {
		t.Fatalf("existing tid should not be overwritten, got %v", out["tid"])
	}
}

func TestApply_Okta_RemapsEmail(t *testing.T) {
	claims := map[string]any{"sub": "u1", "email": "a@b.com"}
	out := Okta.Apply(claims)
	if _, ok := out["email"]; ok {
		t.Fatal("email key should be remapped to login")
	}
	if out["login"] != "a@b.com" {
		t.Fatalf("expected login=a@b.com, got %v", out["login"])
	}
}

func TestApply_GoogleWorkspace_AddsEmailVerified(t *testing.T) {
	claims := map[string]any{"sub": "u1", "email": "a@b.com"}
	out := GoogleWorkspace.Apply(claims)
	if out["email_verified"] != true {
		t.Fatalf("expected email_verified=true, got %v", out["email_verified"])
	}
	if out["hd"] != "example.com" {
		t.Fatalf("expected hd=example.com, got %v", out["hd"])
	}
}

func TestApply_NilPersonalityPassesThrough(t *testing.T) {
	var p *Personality
	claims := map[string]any{"sub": "u1", "email": "a@b.com"}
	out := p.Apply(claims)
	if out["email"] != "a@b.com" {
		t.Fatalf("nil personality should pass through claims unchanged")
	}
}

func TestGet_KnownID(t *testing.T) {
	p, ok := Get("azure-ad")
	if !ok {
		t.Fatal("expected azure-ad to be found")
	}
	if p.ID != "azure-ad" {
		t.Fatalf("expected ID azure-ad, got %s", p.ID)
	}
}

func TestGet_UnknownID_ReturnsDefault(t *testing.T) {
	p, ok := Get("not-a-real-provider")
	if ok {
		t.Fatal("expected ok=false for unknown provider")
	}
	if p != Default {
		t.Fatal("expected Default personality for unknown ID")
	}
}

func TestGet_CaseInsensitive(t *testing.T) {
	p, ok := Get("OKTA")
	if !ok {
		t.Fatal("expected okta to be found case-insensitively")
	}
	if p.ID != "okta" {
		t.Fatalf("expected ID okta, got %s", p.ID)
	}
}

func TestAll_ContainsBuiltins(t *testing.T) {
	all := All()
	ids := make(map[string]bool, len(all))
	for _, p := range all {
		ids[p.ID] = true
	}
	for _, want := range []string{"default", "okta", "azure-ad", "google-workspace", "google", "github", "onelogin"} {
		if !ids[want] {
			t.Errorf("All() missing personality %q", want)
		}
	}
}
