// Package personality defines provider personalities — named sets of claim
// mappings that make Authpilot's issued tokens look like those from a real
// identity provider (Okta, Azure AD, Google, etc.).
//
// A personality remaps standard Authpilot claim names to the provider-idiomatic
// names. For example, Azure AD calls the email field "preferred_username" and
// adds a "tid" (tenant ID) claim; this package models that mapping so token
// consumers can test against realistic payloads without a real IdP.
package personality

import "strings"

// Personality is a named set of claim remappings and extra static claims.
type Personality struct {
	// ID is the machine-readable identifier (e.g. "azure-ad").
	ID string
	// Name is the human-readable display name.
	Name string
	// ClaimMappings renames Authpilot's standard claim keys to provider-specific
	// ones. Key = Authpilot claim name, value = provider claim name.
	// Claims not listed here are emitted as-is.
	ClaimMappings map[string]string
	// ExtraClaims are static additional claims always added to the token.
	// These represent provider-specific claims that have no Authpilot equivalent.
	ExtraClaims map[string]any
}

// Apply returns a new claims map with this personality's mappings applied.
// It renames keys per ClaimMappings and merges ExtraClaims (which do not
// overwrite existing values).
func (p *Personality) Apply(claims map[string]any) map[string]any {
	if p == nil {
		return claims
	}
	out := make(map[string]any, len(claims)+len(p.ExtraClaims))

	// Copy original claims, renaming any that have a mapping.
	for k, v := range claims {
		if mapped, ok := p.ClaimMappings[k]; ok {
			out[mapped] = v
		} else {
			out[k] = v
		}
	}

	// Add extra static claims (only if not already present after remapping).
	for k, v := range p.ExtraClaims {
		if _, exists := out[k]; !exists {
			out[k] = v
		}
	}

	return out
}

// ---- Built-in personalities ----

var (
	// Default is the plain Authpilot token — no remapping.
	Default = &Personality{ID: "default", Name: "Authpilot Default"}

	Okta = &Personality{
		ID:   "okta",
		Name: "Okta",
		ClaimMappings: map[string]string{
			"email": "login",
			"name":  "name", // same key, no change
		},
		ExtraClaims: map[string]any{
			"ver": 1,
			"jti": "okta-jti-placeholder",
		},
	}

	AzureAD = &Personality{
		ID:   "azure-ad",
		Name: "Azure AD / Entra ID",
		ClaimMappings: map[string]string{
			"email":  "preferred_username",
			"name":   "name",
			"groups": "groups",
		},
		ExtraClaims: map[string]any{
			"tid": "common",
			"ver": "2.0",
		},
	}

	GoogleWorkspace = &Personality{
		ID:   "google-workspace",
		Name: "Google Workspace",
		ClaimMappings: map[string]string{
			"email": "email",
			"name":  "name",
		},
		ExtraClaims: map[string]any{
			"hd":              "example.com",
			"email_verified":  true,
			"locale":          "en",
		},
	}

	Google = &Personality{
		ID:   "google",
		Name: "Google",
		ClaimMappings: map[string]string{
			"email": "email",
			"name":  "name",
		},
		ExtraClaims: map[string]any{
			"email_verified": true,
			"locale":         "en",
		},
	}

	GitHub = &Personality{
		ID:   "github",
		Name: "GitHub",
		ClaimMappings: map[string]string{
			"email": "email",
			"name":  "name",
			"sub":   "sub",
		},
		ExtraClaims: map[string]any{
			"login": "github-user",
		},
	}

	OneLogin = &Personality{
		ID:   "onelogin",
		Name: "OneLogin",
		ClaimMappings: map[string]string{
			"email": "email",
			"name":  "name",
		},
		ExtraClaims: map[string]any{
			"params": map[string]any{},
		},
	}
)

// all is the registry of built-in personalities by ID.
var all = map[string]*Personality{
	"default":          Default,
	"okta":             Okta,
	"azure-ad":         AzureAD,
	"google-workspace": GoogleWorkspace,
	"google":           Google,
	"github":           GitHub,
	"onelogin":         OneLogin,
}

// Get returns the personality for the given ID (case-insensitive).
// Returns Default and false if not found.
func Get(id string) (*Personality, bool) {
	p, ok := all[strings.ToLower(strings.TrimSpace(id))]
	if !ok {
		return Default, false
	}
	return p, true
}

// All returns a slice of all registered personalities.
func All() []*Personality {
	out := make([]*Personality, 0, len(all))
	for _, p := range all {
		out = append(out, p)
	}
	return out
}
