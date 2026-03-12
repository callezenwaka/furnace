package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/gorilla/mux"

	"authpilot/server/internal/domain"
	"authpilot/server/internal/store"
)

type Dependencies struct {
	Users    store.UserStore
	Groups   store.GroupStore
	Flows    store.FlowStore
	Sessions store.SessionStore
	AdminStaticDir string
}

func NewRouter(dep Dependencies) http.Handler {
	r := mux.NewRouter()
	registerAdminRoutes(r, dep.AdminStaticDir)

	r.HandleFunc("/health", healthHandler).Methods(http.MethodGet)
	r.HandleFunc("/login", loginPageHandler(dep.Flows, dep.Users)).Methods(http.MethodGet)
	r.HandleFunc("/login/select-user", loginSelectUserHandler(dep.Flows, dep.Users)).Methods(http.MethodPost)
	r.HandleFunc("/login/mfa", loginMFAHandler(dep.Flows, dep.Users)).Methods(http.MethodGet)
	r.HandleFunc("/login/mfa", loginMFASubmitHandler(dep.Flows, dep.Users)).Methods(http.MethodPost)
	r.HandleFunc("/login/complete", loginCompleteHandler(dep.Flows, dep.Users)).Methods(http.MethodGet)

	api := r.PathPrefix("/api/v1").Subrouter()
	api.HandleFunc("/users", listUsersHandler(dep.Users)).Methods(http.MethodGet)
	api.HandleFunc("/users", createUserHandler(dep.Users)).Methods(http.MethodPost)
	api.HandleFunc("/users/{id}", getUserHandler(dep.Users)).Methods(http.MethodGet)
	api.HandleFunc("/users/{id}", updateUserHandler(dep.Users)).Methods(http.MethodPut)
	api.HandleFunc("/users/{id}", deleteUserHandler(dep.Users)).Methods(http.MethodDelete)

	api.HandleFunc("/groups", listGroupsHandler(dep.Groups)).Methods(http.MethodGet)
	api.HandleFunc("/groups", createGroupHandler(dep.Groups)).Methods(http.MethodPost)
	api.HandleFunc("/groups/{id}", getGroupHandler(dep.Groups)).Methods(http.MethodGet)
	api.HandleFunc("/groups/{id}", updateGroupHandler(dep.Groups)).Methods(http.MethodPut)
	api.HandleFunc("/groups/{id}", deleteGroupHandler(dep.Groups)).Methods(http.MethodDelete)

	api.HandleFunc("/flows", listFlowsHandler(dep.Flows)).Methods(http.MethodGet)
	api.HandleFunc("/flows", createFlowHandler(dep.Flows)).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}", getFlowHandler(dep.Flows)).Methods(http.MethodGet)
	api.HandleFunc("/flows/{id}/select-user", selectUserFlowHandler(dep.Flows, dep.Users)).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}/verify-mfa", verifyMFAFlowHandler(dep.Flows, dep.Users)).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}/approve", approveFlowHandler(dep.Flows, dep.Users)).Methods(http.MethodPost)
	api.HandleFunc("/flows/{id}/deny", denyFlowHandler(dep.Flows)).Methods(http.MethodPost)

	return r
}

func registerAdminRoutes(r *mux.Router, adminStaticDir string) {
	if adminStaticDir == "" {
		adminStaticDir = filepath.Join("server", "web", "static", "admin")
	}

	adminIndexPath := filepath.Join(adminStaticDir, "index.html")
	adminAssets := http.StripPrefix("/admin/", http.FileServer(http.Dir(adminStaticDir)))

	r.PathPrefix("/admin/assets/").Handler(adminAssets)
	r.Handle("/admin/vite.svg", adminAssets)
	r.HandleFunc("/admin", serveAdminIndex(adminIndexPath))
	r.PathPrefix("/admin/").HandlerFunc(serveAdminIndex(adminIndexPath))
}

func serveAdminIndex(indexPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(indexPath); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				writeError(w, http.StatusNotFound, "admin_spa_missing", "admin SPA index not found; run `make admin-build`")
				return
			}
			writeError(w, http.StatusInternalServerError, "admin_spa_unavailable", err.Error())
			return
		}

		http.ServeFile(w, r, indexPath)
	}
}

func healthHandler(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"time":   time.Now().UTC(),
	})
}

func listUsersHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		result, err := users.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_users_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func createUserHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := decodeUser(w, r.Body)
		if !ok {
			return
		}
		if user.ID == "" {
			writeError(w, http.StatusBadRequest, "validation_error", "id is required")
			return
		}
		if user.CreatedAt.IsZero() {
			user.CreatedAt = time.Now().UTC()
		}
		created, err := users.Create(user)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "create_user_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

func getUserHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		user, err := users.GetByID(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "get_user_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, user)
	}
}

func updateUserHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		user, ok := decodeUser(w, r.Body)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		user.ID = id
		if user.CreatedAt.IsZero() {
			user.CreatedAt = time.Now().UTC()
		}
		updated, err := users.Update(user)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "update_user_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func deleteUserHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		if err := users.Delete(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "user not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "delete_user_failed", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func listGroupsHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		result, err := groups.List()
		if err != nil {
			writeError(w, http.StatusInternalServerError, "list_groups_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, result)
	}
}

func createGroupHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		group, ok := decodeGroup(w, r.Body)
		if !ok {
			return
		}
		if group.ID == "" {
			writeError(w, http.StatusBadRequest, "validation_error", "id is required")
			return
		}
		if group.CreatedAt.IsZero() {
			group.CreatedAt = time.Now().UTC()
		}
		created, err := groups.Create(group)
		if err != nil {
			writeError(w, http.StatusInternalServerError, "create_group_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, created)
	}
}

func getGroupHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		group, err := groups.GetByID(id)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "group not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "get_group_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, group)
	}
}

func updateGroupHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		group, ok := decodeGroup(w, r.Body)
		if !ok {
			return
		}
		id := mux.Vars(r)["id"]
		group.ID = id
		if group.CreatedAt.IsZero() {
			group.CreatedAt = time.Now().UTC()
		}
		updated, err := groups.Update(group)
		if err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "group not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "update_group_failed", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, updated)
	}
}

func deleteGroupHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		if err := groups.Delete(id); err != nil {
			if errors.Is(err, store.ErrNotFound) {
				writeError(w, http.StatusNotFound, "not_found", "group not found")
				return
			}
			writeError(w, http.StatusInternalServerError, "delete_group_failed", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func decodeUser(w http.ResponseWriter, body io.Reader) (domain.User, bool) {
	var user domain.User
	if err := json.NewDecoder(body).Decode(&user); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return domain.User{}, false
	}
	return user, true
}

func decodeGroup(w http.ResponseWriter, body io.Reader) (domain.Group, bool) {
	var group domain.Group
	if err := json.NewDecoder(body).Decode(&group); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err.Error())
		return domain.Group{}, false
	}
	return group, true
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, status int, code string, message string) {
	writeJSON(w, status, map[string]any{
		"error": map[string]string{
			"code":    code,
			"message": message,
		},
	})
}
