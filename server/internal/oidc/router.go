package oidc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"authpilot/server/internal/domain"
	flowengine "authpilot/server/internal/flow"
	"authpilot/server/internal/store"
)

// RouterDeps groups everything the OIDC router needs.
type RouterDeps struct {
	Flows     store.FlowStore
	Users     store.UserStore
	Sessions  store.SessionStore
	KeyMgr    *KeyManager
	Issuer    *Issuer
	IssuerURL string // e.g. "http://localhost:8026"
	LoginURL  string // e.g. "http://localhost:8025/login"
}

func NewRouter(dep RouterDeps) http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/.well-known/openid-configuration", discoveryHandler(dep)).Methods(http.MethodGet)
	r.HandleFunc("/.well-known/jwks.json", jwksHandler(dep.KeyMgr)).Methods(http.MethodGet)
	r.HandleFunc("/authorize", authorizeHandler(dep)).Methods(http.MethodGet)
	r.HandleFunc("/authorize/complete", authorizeCompleteHandler(dep)).Methods(http.MethodGet)
	r.HandleFunc("/token", tokenHandler(dep)).Methods(http.MethodPost)
	r.HandleFunc("/userinfo", userinfoHandler(dep)).Methods(http.MethodGet, http.MethodPost)
	r.HandleFunc("/revoke", revokeHandler()).Methods(http.MethodPost)

	return r
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

func discoveryHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		base := dep.IssuerURL
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                base,
			"authorization_endpoint":                base + "/authorize",
			"token_endpoint":                        base + "/token",
			"userinfo_endpoint":                     base + "/userinfo",
			"jwks_uri":                              base + "/.well-known/jwks.json",
			"revocation_endpoint":                   base + "/revoke",
			"response_types_supported":              []string{"code"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{"RS256"},
			"scopes_supported":                      []string{"openid", "profile", "email", "offline_access"},
			"token_endpoint_auth_methods_supported": []string{"client_secret_post", "client_secret_basic", "none"},
			"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "email", "name", "groups"},
			"grant_types_supported":                 []string{"authorization_code", "refresh_token"},
			"code_challenge_methods_supported":      []string{"S256", "plain"},
		})
	}
}

// ---------------------------------------------------------------------------
// JWKS
// ---------------------------------------------------------------------------

func jwksHandler(km *KeyManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, km.JWKS())
	}
}

// ---------------------------------------------------------------------------
// Authorize
// ---------------------------------------------------------------------------

func authorizeHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		clientID := strings.TrimSpace(q.Get("client_id"))
		redirectURI := strings.TrimSpace(q.Get("redirect_uri"))
		responseType := strings.TrimSpace(q.Get("response_type"))
		scope := strings.TrimSpace(q.Get("scope"))
		state := strings.TrimSpace(q.Get("state"))
		nonce := strings.TrimSpace(q.Get("nonce"))
		challenge := strings.TrimSpace(q.Get("code_challenge"))
		challengeMethod := strings.TrimSpace(q.Get("code_challenge_method"))

		if clientID == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "client_id is required")
			return
		}
		if redirectURI == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "redirect_uri is required")
			return
		}
		if responseType != "code" {
			redirectWithError(w, r, redirectURI, state, "unsupported_response_type", "only 'code' is supported")
			return
		}
		if challenge == "" {
			redirectWithError(w, r, redirectURI, state, "invalid_request", "code_challenge is required (PKCE mandatory)")
			return
		}

		scopes := splitScope(scope)

		now := time.Now().UTC()
		flow := domain.Flow{
			ID:            fmt.Sprintf("flow_%d", now.UnixNano()),
			State:         string(flowengine.StateInitiated),
			Scenario:      string(flowengine.ScenarioNormal),
			Protocol:      "oidc",
			ClientID:      clientID,
			RedirectURI:   redirectURI,
			Scopes:        scopes,
			ResponseType:  responseType,
			OAuthState:    state,
			Nonce:         nonce,
			PKCEChallenge: challenge,
			PKCEMethod:    challengeMethod,
			CreatedAt:     now,
			ExpiresAt:     now.Add(30 * time.Minute),
		}

		created, err := dep.Flows.Create(flow)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to create flow")
			return
		}

		loginURL := dep.LoginURL + "?flow_id=" + created.ID
		http.Redirect(w, r, loginURL, http.StatusFound)
	}
}

// ---------------------------------------------------------------------------
// Authorize Complete — called by the login UI after the flow reaches complete.
// ---------------------------------------------------------------------------

func authorizeCompleteHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flowID := strings.TrimSpace(r.URL.Query().Get("flow_id"))
		if flowID == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "flow_id is required")
			return
		}

		flow, err := dep.Flows.GetByID(flowID)
		if err != nil {
			writeOAuthError(w, http.StatusNotFound, "invalid_request", "flow not found")
			return
		}
		if flow.State != string(flowengine.StateComplete) {
			writeOAuthError(w, http.StatusConflict, "invalid_request", "flow is not complete")
			return
		}
		if flow.RedirectURI == "" {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "flow has no redirect_uri (not an OIDC flow)")
			return
		}

		// Generate auth code and store it on the flow.
		code, err := randomID(16)
		if err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to generate auth code")
			return
		}
		flow.AuthCode = code
		if _, err := dep.Flows.Update(flow); err != nil {
			writeOAuthError(w, http.StatusInternalServerError, "server_error", "failed to store auth code")
			return
		}

		redirectTo, _ := url.Parse(flow.RedirectURI)
		q := redirectTo.Query()
		q.Set("code", code)
		if flow.OAuthState != "" {
			q.Set("state", flow.OAuthState)
		}
		redirectTo.RawQuery = q.Encode()
		http.Redirect(w, r, redirectTo.String(), http.StatusFound)
	}
}

// ---------------------------------------------------------------------------
// Token
// ---------------------------------------------------------------------------

func tokenHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			writeOAuthError(w, http.StatusBadRequest, "invalid_request", "cannot parse form")
			return
		}

		grantType := strings.TrimSpace(r.FormValue("grant_type"))

		switch grantType {
		case "authorization_code":
			handleAuthCodeGrant(w, r, dep)
		case "refresh_token":
			handleRefreshGrant(w, r, dep)
		default:
			writeOAuthError(w, http.StatusBadRequest, "unsupported_grant_type", "supported: authorization_code, refresh_token")
		}
	}
}

func handleAuthCodeGrant(w http.ResponseWriter, r *http.Request, dep RouterDeps) {
	code := strings.TrimSpace(r.FormValue("code"))
	redirectURI := strings.TrimSpace(r.FormValue("redirect_uri"))
	verifier := strings.TrimSpace(r.FormValue("code_verifier"))

	if code == "" {
		writeOAuthError(w, http.StatusBadRequest, "invalid_request", "code is required")
		return
	}

	// Find the flow by auth code — scan all flows (small set in dev).
	flows, err := dep.Flows.List()
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "flow lookup failed")
		return
	}
	var matched *domain.Flow
	for idx := range flows {
		if flows[idx].AuthCode == code {
			matched = &flows[idx]
			break
		}
	}
	if matched == nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "code not found or already redeemed")
		return
	}
	if matched.State != string(flowengine.StateComplete) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "flow is not complete")
		return
	}
	if time.Now().UTC().After(matched.ExpiresAt) {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "authorization code expired")
		return
	}
	if redirectURI != "" && redirectURI != matched.RedirectURI {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "redirect_uri mismatch")
		return
	}

	if err := VerifyPKCE(matched.PKCEChallenge, matched.PKCEMethod, verifier); err != nil {
		writeOAuthError(w, http.StatusBadRequest, "invalid_grant", err.Error())
		return
	}

	user, err := dep.Users.GetByID(matched.UserID)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "user not found")
		return
	}

	// Check expired_token scenario — issue a token that expires immediately.
	flow := *matched
	issuer := dep.Issuer
	if flowengine.NormalizeScenario(flow.Scenario) == flowengine.ScenarioExpiredToken {
		// Temporarily swap in a 0-second TTL config for this issuance.
		expiredIssuer := NewIssuer(dep.KeyMgr, TokenConfig{
			AccessTokenTTL:  -1 * time.Second,
			IDTokenTTL:      -1 * time.Second,
			RefreshTokenTTL: dep.Issuer.cfg.RefreshTokenTTL,
		}, dep.Issuer.issuer)
		issuer = expiredIssuer
	}

	tokens, err := issuer.Issue(flow, user)
	if err != nil {
		writeOAuthError(w, http.StatusInternalServerError, "server_error", "token issuance failed")
		return
	}

	// Consume the auth code.
	matched.AuthCode = ""
	_, _ = dep.Flows.Update(*matched)

	// Create a session record.
	now := time.Now().UTC()
	session := domain.Session{
		ID:        fmt.Sprintf("sess_%d", now.UnixNano()),
		UserID:    matched.UserID,
		FlowID:    matched.ID,
		CreatedAt: now,
		ExpiresAt: now.Add(dep.Issuer.cfg.RefreshTokenTTL),
	}
	_, _ = dep.Sessions.Create(session)

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, tokens)
}

func handleRefreshGrant(w http.ResponseWriter, r *http.Request, dep RouterDeps) {
	// Refresh tokens are opaque; we don't store them in M3.
	// Return invalid_grant — clients should restart the flow.
	writeOAuthError(w, http.StatusBadRequest, "invalid_grant", "refresh tokens are not persisted in this build; restart the authorization flow")
}

// ---------------------------------------------------------------------------
// Userinfo
// ---------------------------------------------------------------------------

func userinfoHandler(dep RouterDeps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := bearerToken(r)
		if token == "" {
			w.Header().Set("WWW-Authenticate", `Bearer realm="authpilot"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "bearer token required")
			return
		}

		// Parse the JWT to get the sub claim (we trust our own signature here
		// since this is a local dev tool — full validation is optional).
		sub, err := subFromJWT(token)
		if err != nil {
			w.Header().Set("WWW-Authenticate", `Bearer realm="authpilot", error="invalid_token"`)
			writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "cannot parse access token")
			return
		}

		user, err := dep.Users.GetByID(sub)
		if err != nil {
			writeOAuthError(w, http.StatusUnauthorized, "invalid_token", "user not found")
			return
		}

		claims := map[string]any{
			"sub":   user.ID,
			"email": user.Email,
			"name":  user.DisplayName,
		}
		if len(user.Groups) > 0 {
			claims["groups"] = user.Groups
		}
		for k, v := range user.Claims {
			if _, exists := claims[k]; !exists {
				claims[k] = v
			}
		}

		writeJSON(w, http.StatusOK, claims)
	}
}

// ---------------------------------------------------------------------------
// Revoke
// ---------------------------------------------------------------------------

func revokeHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Accept and ignore — tokens are short-lived in a dev context.
		w.WriteHeader(http.StatusOK)
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func bearerToken(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return strings.TrimSpace(r.FormValue("access_token"))
}

// subFromJWT extracts the "sub" claim from an unsecured/signed JWT without
// verifying the signature (acceptable for a local dev server).
func subFromJWT(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid jwt format")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return "", fmt.Errorf("unmarshal claims: %w", err)
	}
	sub, _ := claims["sub"].(string)
	if sub == "" {
		return "", fmt.Errorf("sub claim missing")
	}
	return sub, nil
}


func splitScope(scope string) []string {
	if scope == "" {
		return nil
	}
	parts := strings.Fields(scope)
	return parts
}

func redirectWithError(w http.ResponseWriter, r *http.Request, redirectURI, state, errCode, desc string) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		writeOAuthError(w, http.StatusBadRequest, errCode, desc)
		return
	}
	q := u.Query()
	q.Set("error", errCode)
	q.Set("error_description", desc)
	if state != "" {
		q.Set("state", state)
	}
	u.RawQuery = q.Encode()
	http.Redirect(w, r, u.String(), http.StatusFound)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeOAuthError(w http.ResponseWriter, status int, errCode, desc string) {
	writeJSON(w, status, map[string]string{
		"error":             errCode,
		"error_description": desc,
	})
}
