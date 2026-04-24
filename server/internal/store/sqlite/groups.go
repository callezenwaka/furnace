package sqlite

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

type GroupStore struct {
	db *sql.DB
}

func (s *Store) Groups() *GroupStore {
	return &GroupStore{db: s.db}
}

func (s *GroupStore) Create(group domain.Group) (domain.Group, error) {
	memberJSON, err := json.Marshal(group.MemberIDs)
	if err != nil {
		return domain.Group{}, fmt.Errorf("marshal group members: %w", err)
	}

	_, err = s.db.Exec(`
		INSERT INTO groups (id, name, display_name, member_ids_json, created_at)
		VALUES (?, ?, ?, ?, ?)
	`, group.ID, group.Name, group.DisplayName, string(memberJSON), group.CreatedAt.UTC().Format(time.RFC3339Nano))
	if err != nil {
		return domain.Group{}, fmt.Errorf("insert group: %w", err)
	}
	return group, nil
}

func (s *GroupStore) GetByID(id string) (domain.Group, error) {
	row := s.db.QueryRow(`
		SELECT id, name, display_name, member_ids_json, created_at
		FROM groups
		WHERE id = ?
	`, id)
	return scanGroup(row)
}

func (s *GroupStore) List() ([]domain.Group, error) {
	rows, err := s.db.Query(`
		SELECT id, name, display_name, member_ids_json, created_at
		FROM groups
	`)
	if err != nil {
		return nil, fmt.Errorf("list groups: %w", err)
	}
	defer rows.Close()

	groups := make([]domain.Group, 0)
	for rows.Next() {
		group, err := scanGroup(rows)
		if err != nil {
			return nil, err
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate groups: %w", err)
	}

	sort.Slice(groups, func(i, j int) bool { return groups[i].ID < groups[j].ID })
	return groups, nil
}

func (s *GroupStore) Update(group domain.Group) (domain.Group, error) {
	memberJSON, err := json.Marshal(group.MemberIDs)
	if err != nil {
		return domain.Group{}, fmt.Errorf("marshal group members: %w", err)
	}

	res, err := s.db.Exec(`
		UPDATE groups
		SET name = ?, display_name = ?, member_ids_json = ?, created_at = ?
		WHERE id = ?
	`, group.Name, group.DisplayName, string(memberJSON), group.CreatedAt.UTC().Format(time.RFC3339Nano), group.ID)
	if err != nil {
		return domain.Group{}, fmt.Errorf("update group: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return domain.Group{}, fmt.Errorf("check affected rows: %w", err)
	}
	if affected == 0 {
		return domain.Group{}, store.ErrNotFound
	}
	return group, nil
}

func (s *GroupStore) Delete(id string) error {
	res, err := s.db.Exec(`DELETE FROM groups WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("delete group: %w", err)
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

func scanGroup(scn scanner) (domain.Group, error) {
	var group domain.Group
	var memberIDsJSON string
	var createdAt string

	err := scn.Scan(
		&group.ID,
		&group.Name,
		&group.DisplayName,
		&memberIDsJSON,
		&createdAt,
	)
	if err != nil {
		if err == sql.ErrNoRows {
			return domain.Group{}, store.ErrNotFound
		}
		return domain.Group{}, fmt.Errorf("scan group: %w", err)
	}

	if err := json.Unmarshal([]byte(memberIDsJSON), &group.MemberIDs); err != nil {
		return domain.Group{}, fmt.Errorf("decode group members: %w", err)
	}

	parsed, err := time.Parse(time.RFC3339Nano, createdAt)
	if err != nil {
		return domain.Group{}, fmt.Errorf("parse group created_at: %w", err)
	}
	group.CreatedAt = parsed
	return group, nil
}
