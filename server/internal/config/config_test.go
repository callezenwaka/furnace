package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConfigPrecedenceRuntimeOverEnvOverYAMLOverDefaults(t *testing.T) {
	t.Setenv("AUTHPILOT_HTTP_ADDR", ":9001")
	t.Setenv("AUTHPILOT_PERSISTENCE_ENABLED", "true")

	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "config.yaml")
	yaml := []byte(`
http_addr: ":9000"
persistence:
  enabled: false
  sqlite_path: "/tmp/from-yaml.db"
cleanup:
  interval: "30s"
`)
	if err := os.WriteFile(cfgPath, yaml, 0o644); err != nil {
		t.Fatalf("write yaml: %v", err)
	}

	interval := 5 * time.Second
	runtime := RuntimeOverrides{
		HTTPAddr:           ":9010",
		PersistenceEnabled: boolPtr(false),
		CleanupInterval:    &interval,
	}

	cfg, err := Load(cfgPath, runtime)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}

	if cfg.HTTPAddr != ":9010" {
		t.Fatalf("expected runtime HTTP addr, got %q", cfg.HTTPAddr)
	}
	if cfg.Persistence.Enabled {
		t.Fatalf("expected runtime persistence=false, got true")
	}
	if cfg.Persistence.SQLitePath != "/tmp/from-yaml.db" {
		t.Fatalf("expected sqlite path from yaml, got %q", cfg.Persistence.SQLitePath)
	}
	if cfg.Cleanup.Interval != 5*time.Second {
		t.Fatalf("expected cleanup interval 5s, got %v", cfg.Cleanup.Interval)
	}
}

func TestConfigValidation(t *testing.T) {
	cfg := Defaults()
	cfg.LogLevel = "nope"
	if err := validate(cfg); err == nil {
		t.Fatal("expected log level validation error")
	}
}

func boolPtr(v bool) *bool {
	return &v
}
