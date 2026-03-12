package sqlite

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func New(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("create sqlite directory: %w", err)
	}

	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite database: %w", err)
	}

	store := &Store{db: db}
	if err := store.migrate(); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error {
	return s.db.Close()
}

func (s *Store) migrate() error {
	stmts := []string{
		`CREATE TABLE IF NOT EXISTS users (
			id TEXT PRIMARY KEY,
			email TEXT NOT NULL,
			display_name TEXT NOT NULL,
			groups_json TEXT NOT NULL,
			mfa_method TEXT NOT NULL,
			next_flow TEXT NOT NULL,
			claims_json TEXT,
			phone_number TEXT,
			created_at TEXT NOT NULL
		);`,
		`CREATE TABLE IF NOT EXISTS groups (
			id TEXT PRIMARY KEY,
			name TEXT NOT NULL,
			display_name TEXT NOT NULL,
			member_ids_json TEXT NOT NULL,
			created_at TEXT NOT NULL
		);`,
	}
	for _, stmt := range stmts {
		if _, err := s.db.Exec(stmt); err != nil {
			return fmt.Errorf("sqlite migration failed: %w", err)
		}
	}
	return nil
}
