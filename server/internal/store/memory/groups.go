package memory

import (
	"sort"
	"sync"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

type GroupStore struct {
	mu     sync.RWMutex
	groups map[string]domain.Group
}

func NewGroupStore() *GroupStore {
	return &GroupStore{groups: make(map[string]domain.Group)}
}

func (s *GroupStore) Create(group domain.Group) (domain.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groups[group.ID] = cloneGroup(group)
	return cloneGroup(group), nil
}

func (s *GroupStore) GetByID(id string) (domain.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	group, ok := s.groups[id]
	if !ok {
		return domain.Group{}, store.ErrNotFound
	}
	return cloneGroup(group), nil
}

func (s *GroupStore) List() ([]domain.Group, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Group, 0, len(s.groups))
	for _, group := range s.groups {
		out = append(out, cloneGroup(group))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *GroupStore) Update(group domain.Group) (domain.Group, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[group.ID]; !ok {
		return domain.Group{}, store.ErrNotFound
	}
	s.groups[group.ID] = cloneGroup(group)
	return cloneGroup(group), nil
}

func (s *GroupStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.groups[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.groups, id)
	return nil
}

func cloneGroup(in domain.Group) domain.Group {
	out := in
	out.MemberIDs = append([]string(nil), in.MemberIDs...)
	return out
}
