package sqlite

import (
	"database/sql"
	"fmt"
	"sort"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

type AdminStore struct {
	db *sql.DB
}

func (s *Store) Admins() *AdminStore {
	return &AdminStore{db: s.db}
}

func (s *AdminStore) Create(admin domain.Admin) (domain.Admin, error) {
	_, err := s.db.Exec(`
		INSERT INTO admins (id, username, display_name, password_hash, active, created_at)
		VALUES (?, ?, ?, ?, ?, ?)
	`, admin.ID, admin.Username, admin.DisplayName, admin.PasswordHash,
		boolToInt(admin.Active), admin.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return domain.Admin{}, fmt.Errorf("insert admin: %w", err)
	}
	return admin, nil
}

func (s *AdminStore) GetByID(id string) (domain.Admin, error) {
	row := s.db.QueryRow(`
		SELECT id, username, display_name, password_hash, active, created_at
		FROM admins WHERE id = ?
	`, id)
	return scanAdmin(row)
}

func (s *AdminStore) GetByUsername(username string) (domain.Admin, error) {
	row := s.db.QueryRow(`
		SELECT id, username, display_name, password_hash, active, created_at
		FROM admins WHERE username = ?
	`, username)
	return scanAdmin(row)
}

func (s *AdminStore) List() ([]domain.Admin, error) {
	rows, err := s.db.Query(`
		SELECT id, username, display_name, password_hash, active, created_at
		FROM admins
	`)
	if err != nil {
		return nil, fmt.Errorf("list admins: %w", err)
	}
	defer rows.Close()

	admins := make([]domain.Admin, 0)
	for rows.Next() {
		a, err := scanAdmin(rows)
		if err != nil {
			return nil, err
		}
		admins = append(admins, a)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate admins: %w", err)
	}
	sort.Slice(admins, func(i, j int) bool { return admins[i].ID < admins[j].ID })
	return admins, nil
}

func (s *AdminStore) Update(admin domain.Admin) (domain.Admin, error) {
	res, err := s.db.Exec(`
		UPDATE admins
		SET username = ?, display_name = ?, password_hash = ?, active = ?
		WHERE id = ?
	`, admin.Username, admin.DisplayName, admin.PasswordHash, boolToInt(admin.Active), admin.ID)
	if err != nil {
		return domain.Admin{}, fmt.Errorf("update admin: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return domain.Admin{}, fmt.Errorf("check affected rows: %w", err)
	}
	if affected == 0 {
		return domain.Admin{}, store.ErrNotFound
	}
	return admin, nil
}

func (s *AdminStore) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM admins WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete admin: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("check affected rows: %w", err)
	}
	if affected == 0 {
		return store.ErrNotFound
	}
	return nil
}

func (s *AdminStore) CountActive() (int, error) {
	var count int
	err := s.db.QueryRow(`SELECT COUNT(*) FROM admins WHERE active = 1`).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("count active admins: %w", err)
	}
	return count, nil
}

func scanAdmin(s scanner) (domain.Admin, error) {
	var a domain.Admin
	var active int
	var createdAt string
	err := s.Scan(&a.ID, &a.Username, &a.DisplayName, &a.PasswordHash, &active, &createdAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.Admin{}, store.ErrNotFound
		}
		return domain.Admin{}, fmt.Errorf("scan admin: %w", err)
	}
	a.Active = active != 0
	parsed, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return domain.Admin{}, fmt.Errorf("parse admin created_at: %w", err)
	}
	a.CreatedAt = parsed
	return a, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
