package tenant

import "context"

const DefaultTenantID = "default"

type contextKey struct{}

// WithTenant attaches a tenant ID to the context.
func WithTenant(ctx context.Context, tenantID string) context.Context {
	return context.WithValue(ctx, contextKey{}, tenantID)
}

// FromContext extracts the tenant ID from the context.
// Returns DefaultTenantID if none is set — safe for single-tenant callers.
func FromContext(ctx context.Context) string {
	if id, ok := ctx.Value(contextKey{}).(string); ok && id != "" {
		return id
	}
	return DefaultTenantID
}
