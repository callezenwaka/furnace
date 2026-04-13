package tenant

import (
	"context"
	"testing"
)

func TestFromContext_NoValue_ReturnsDefault(t *testing.T) {
	if got := FromContext(context.Background()); got != DefaultTenantID {
		t.Errorf("want %q, got %q", DefaultTenantID, got)
	}
}

func TestWithTenant_RoundTrip(t *testing.T) {
	ctx := WithTenant(context.Background(), "acme")
	if got := FromContext(ctx); got != "acme" {
		t.Errorf("want %q, got %q", "acme", got)
	}
}

func TestFromContext_EmptyString_ReturnsDefault(t *testing.T) {
	ctx := context.WithValue(context.Background(), contextKey{}, "")
	if got := FromContext(ctx); got != DefaultTenantID {
		t.Errorf("want %q, got %q", DefaultTenantID, got)
	}
}

func TestWithTenant_DoesNotAffectParent(t *testing.T) {
	parent := context.Background()
	_ = WithTenant(parent, "acme")
	if got := FromContext(parent); got != DefaultTenantID {
		t.Errorf("parent context should be unchanged, got %q", got)
	}
}
