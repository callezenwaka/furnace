package memory

import (
	"sort"
	"sync"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

type AdminStore struct {
	mu     sync.RWMutex
	admins map[string]domain.Admin
}

func NewAdminStore() *AdminStore {
	return &AdminStore{admins: make(map[string]domain.Admin)}
}

func (s *AdminStore) Create(admin domain.Admin) (domain.Admin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.admins[admin.ID] = admin
	return admin, nil
}

func (s *AdminStore) GetByID(id string) (domain.Admin, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	a, ok := s.admins[id]
	if !ok {
		return domain.Admin{}, store.ErrNotFound
	}
	return a, nil
}

func (s *AdminStore) GetByUsername(username string) (domain.Admin, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, a := range s.admins {
		if a.Username == username {
			return a, nil
		}
	}
	return domain.Admin{}, store.ErrNotFound
}

func (s *AdminStore) List() ([]domain.Admin, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Admin, 0, len(s.admins))
	for _, a := range s.admins {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *AdminStore) Update(admin domain.Admin) (domain.Admin, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.admins[admin.ID]; !ok {
		return domain.Admin{}, store.ErrNotFound
	}
	s.admins[admin.ID] = admin
	return admin, nil
}

func (s *AdminStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.admins[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.admins, id)
	return nil
}

func (s *AdminStore) CountActive() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, a := range s.admins {
		if a.Active {
			count++
		}
	}
	return count, nil
}
