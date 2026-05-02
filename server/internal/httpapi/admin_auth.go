package httpapi

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"furnace/server/internal/domain"
	"furnace/server/internal/platform/password"
	"furnace/server/internal/store"
	"furnace/server/web"
)

const (
	adminCookieName = "furnace_admin"
	adminCookieTTL  = 12 * time.Hour
)

// signAdminCookie produces the cookie value for the given admin ID.
// Format: base64url(adminID|expUnix) + "." + base64url(HMAC-SHA256)
func signAdminCookie(adminID string, key []byte) string {
	exp := time.Now().Add(adminCookieTTL).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(adminID + "|" + strconv.FormatInt(exp, 10)))
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig
}

// verifyAdminCookie validates the cookie value and returns the admin ID.
func verifyAdminCookie(value string, key []byte) (string, error) {
	parts := strings.SplitN(value, ".", 2)
	if len(parts) != 2 {
		return "", errors.New("malformed cookie")
	}
	payload, sig := parts[0], parts[1]

	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(payload))
	expected := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expected)) {
		return "", errors.New("invalid cookie signature")
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", fmt.Errorf("decode payload: %w", err)
	}
	idx := strings.LastIndex(string(raw), "|")
	if idx < 0 {
		return "", errors.New("malformed payload")
	}
	adminID := string(raw[:idx])
	exp, err := strconv.ParseInt(string(raw[idx+1:]), 10, 64)
	if err != nil {
		return "", fmt.Errorf("parse expiry: %w", err)
	}
	if time.Now().Unix() > exp {
		return "", errors.New("cookie expired")
	}
	return adminID, nil
}

func setAdminCookie(w http.ResponseWriter, r *http.Request, adminID string, key []byte) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    signAdminCookie(adminID, key),
		Path:     "/admin",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		MaxAge:   int(adminCookieTTL.Seconds()),
	})
}

func clearAdminCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     adminCookieName,
		Value:    "",
		Path:     "/admin",
		HttpOnly: true,
		MaxAge:   -1,
	})
}

func getAdminIDFromRequest(r *http.Request, key []byte) (string, error) {
	cookie, err := r.Cookie(adminCookieName)
	if err != nil {
		return "", err
	}
	return verifyAdminCookie(cookie.Value, key)
}

// requireAdminSession wraps admin SPA handlers to enforce cookie auth.
// Redirects to /admin/login when no valid session cookie is present.
func requireAdminSession(admins store.AdminStore, key []byte, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		adminID, err := getAdminIDFromRequest(r, key)
		if err != nil {
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		admin, err := admins.GetByID(adminID)
		if err != nil || !admin.Active {
			clearAdminCookie(w)
			http.Redirect(w, r, "/admin/login", http.StatusFound)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// adminLoginPageHandler serves GET /admin/login.
func adminLoginPageHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		errMsg := ""
		switch r.URL.Query().Get("error") {
		case "invalid_credentials":
			errMsg = "Invalid username or password."
		case "account_inactive":
			errMsg = "Account is inactive."
		case "credentials_required":
			errMsg = "Username and password are required."
		}
		tmpl, err := web.ParseTemplate("admin_login.html")
		if err != nil {
			writeError(w, http.StatusInternalServerError, "template_error", err.Error())
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_ = tmpl.Execute(w, map[string]any{"Error": errMsg, "HasError": errMsg != ""})
	}
}

// adminLoginSubmitHandler handles POST /admin/login.
func adminLoginSubmitHandler(admins store.AdminStore, key []byte) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			http.Redirect(w, r, "/admin/login?error=credentials_required", http.StatusSeeOther)
			return
		}
		username := strings.TrimSpace(r.FormValue("username"))
		pw := r.FormValue("password")
		if username == "" || pw == "" {
			http.Redirect(w, r, "/admin/login?error=credentials_required", http.StatusSeeOther)
			return
		}
		admin, err := admins.GetByUsername(username)
		if err != nil {
			http.Redirect(w, r, "/admin/login?error=invalid_credentials", http.StatusSeeOther)
			return
		}
		if !admin.Active {
			http.Redirect(w, r, "/admin/login?error=account_inactive", http.StatusSeeOther)
			return
		}
		match, rehash, err := password.Verify(admin.PasswordHash, pw)
		if err != nil || !match {
			http.Redirect(w, r, "/admin/login?error=invalid_credentials", http.StatusSeeOther)
			return
		}
		if rehash {
			if newHash, hashErr := password.Hash(pw); hashErr == nil {
				admin.PasswordHash = newHash
				_, _ = admins.Update(admin)
			}
		}
		setAdminCookie(w, r, admin.ID, key)
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	}
}

// adminLogoutHandler handles POST /admin/logout.
func adminLogoutHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		clearAdminCookie(w)
		http.Redirect(w, r, "/admin/login", http.StatusSeeOther)
	}
}

// Admin management API handlers — all behind API key auth.

func adminListHandler(admins store.AdminStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		list, err := admins.List()
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		if list == nil {
			list = []domain.Admin{}
		}
		writeJSON(w, http.StatusOK, list)
	}
}

func adminCreateHandler(admins store.AdminStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username    string `json:"username"`
			DisplayName string `json:"display_name"`
			Password    string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body", false)
			return
		}
		if req.Username == "" || req.Password == "" {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "username and password are required", false)
			return
		}
		hash, err := password.Hash(req.Password)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to hash password", false)
			return
		}
		displayName := req.DisplayName
		if displayName == "" {
			displayName = req.Username
		}
		admin := domain.Admin{
			ID:           fmt.Sprintf("adm_%d", time.Now().UnixNano()),
			Username:     req.Username,
			DisplayName:  displayName,
			PasswordHash: hash,
			Active:       true,
			CreatedAt:    time.Now().UTC(),
		}
		created, err := admins.Create(admin)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

func adminGetHandler(admins store.AdminStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		admin, err := admins.GetByID(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeAPIError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "admin not found", false)
				return
			}
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		writeJSON(w, http.StatusOK, admin)
	}
}

func adminPatchHandler(admins store.AdminStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		var req struct {
			DisplayName *string `json:"display_name"`
			Active      *bool   `json:"active"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body", false)
			return
		}
		admin, err := admins.GetByID(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeAPIError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "admin not found", false)
				return
			}
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		if req.DisplayName != nil {
			admin.DisplayName = *req.DisplayName
		}
		if req.Active != nil {
			if !*req.Active && admin.Active {
				count, countErr := admins.CountActive()
				if countErr == nil && count <= 1 {
					writeAPIError(w, r, http.StatusConflict, "LAST_ADMIN", "cannot deactivate the last active admin", false)
					return
				}
			}
			admin.Active = *req.Active
		}
		updated, err := admins.Update(admin)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func adminDeleteHandler(admins store.AdminStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		admin, err := admins.GetByID(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeAPIError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "admin not found", false)
				return
			}
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		if admin.Active {
			count, countErr := admins.CountActive()
			if countErr == nil && count <= 1 {
				writeAPIError(w, r, http.StatusConflict, "LAST_ADMIN", "cannot delete the last active admin", false)
				return
			}
		}
		if err := admins.Delete(id); err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func adminChangePasswordHandler(admins store.AdminStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		var req struct {
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "invalid JSON body", false)
			return
		}
		if req.Password == "" {
			writeAPIError(w, r, http.StatusBadRequest, "INVALID_REQUEST", "password is required", false)
			return
		}
		admin, err := admins.GetByID(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeAPIError(w, r, http.StatusNotFound, "RESOURCE_NOT_FOUND", "admin not found", false)
				return
			}
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		hash, err := password.Hash(req.Password)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to hash password", false)
			return
		}
		admin.PasswordHash = hash
		updated, err := admins.Update(admin)
		if err != nil {
			writeAPIError(w, r, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error(), false)
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}
