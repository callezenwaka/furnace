package memory

import (
	"sort"
	"sync"
	"time"

	"furnace/server/internal/domain"
	"furnace/server/internal/store"
)

type SessionStore struct {
	mu       sync.RWMutex
	sessions map[string]domain.Session
}

func NewSessionStore() *SessionStore {
	return &SessionStore{sessions: make(map[string]domain.Session)}
}

func (s *SessionStore) Create(session domain.Session) (domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sessions[session.ID] = session
	return session, nil
}

func (s *SessionStore) GetByID(id string) (domain.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	session, ok := s.sessions[id]
	if !ok {
		return domain.Session{}, store.ErrNotFound
	}
	return session, nil
}

func (s *SessionStore) GetByRefreshToken(token string) (domain.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, session := range s.sessions {
		if session.RefreshToken == token {
			return session, nil
		}
	}
	return domain.Session{}, store.ErrNotFound
}

func (s *SessionStore) List() ([]domain.Session, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]domain.Session, 0, len(s.sessions))
	for _, session := range s.sessions {
		out = append(out, session)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func (s *SessionStore) Update(session domain.Session) (domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[session.ID]; !ok {
		return domain.Session{}, store.ErrNotFound
	}
	s.sessions[session.ID] = session
	return session, nil
}

func (s *SessionStore) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.sessions[id]; !ok {
		return store.ErrNotFound
	}
	delete(s.sessions, id)
	return nil
}

func (s *SessionStore) DeleteExpired(now time.Time) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for id, session := range s.sessions {
		if session.ExpiresAt.Before(now) {
			delete(s.sessions, id)
			removed++
		}
	}
	return removed, nil
}
