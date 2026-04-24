package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"furnace/server/internal/store/memory"
)

func TestAdminSPARoutes(t *testing.T) {
	tmp := t.TempDir()

	if err := os.WriteFile(filepath.Join(tmp, "index.html"), []byte("<html><body>admin</body></html>"), 0o644); err != nil {
		t.Fatalf("write admin index: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmp, "assets"), 0o755); err != nil {
		t.Fatalf("mkdir assets: %v", err)
	}
	if err := os.WriteFile(filepath.Join(tmp, "assets", "app.js"), []byte("console.log('ok')"), 0o644); err != nil {
		t.Fatalf("write asset: %v", err)
	}

	router := NewRouter(Dependencies{
		Users:          memory.NewUserStore(),
		Groups:         memory.NewGroupStore(),
		Flows:          memory.NewFlowStore(),
		Sessions:       memory.NewSessionStore(),
		AdminStaticDir: tmp,
	})

	t.Run("serves_admin_index", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "admin") {
			t.Fatalf("expected admin index body, got %q", rr.Body.String())
		}
	})

	t.Run("serves_admin_spa_deep_link", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/users/123", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "admin") {
			t.Fatalf("expected admin index body, got %q", rr.Body.String())
		}
	})

	t.Run("serves_admin_asset", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/admin/assets/app.js", nil)
		rr := httptest.NewRecorder()
		router.ServeHTTP(rr, req)

		if rr.Code != http.StatusOK {
			t.Fatalf("expected 200, got %d", rr.Code)
		}
		if !strings.Contains(rr.Body.String(), "console.log('ok')") {
			t.Fatalf("expected JS asset body, got %q", rr.Body.String())
		}
	})
}
