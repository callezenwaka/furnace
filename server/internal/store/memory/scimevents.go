package memory

import (
	"sync"

	"furnace/server/internal/domain"
)

const defaultSCIMEventCap = 10_000

// SCIMEventStore is a thread-safe in-memory ring buffer for SCIM client events.
type SCIMEventStore struct {
	mu   sync.RWMutex
	buf  []domain.SCIMEvent
	cap  int
	head int
	size int
}

func NewSCIMEventStore(cap int) *SCIMEventStore {
	if cap <= 0 {
		cap = defaultSCIMEventCap
	}
	return &SCIMEventStore{
		buf: make([]domain.SCIMEvent, cap),
		cap: cap,
	}
}

func (s *SCIMEventStore) Append(event domain.SCIMEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.buf[s.head] = event
	s.head = (s.head + 1) % s.cap
	if s.size < s.cap {
		s.size++
	}
}

func (s *SCIMEventStore) List() []domain.SCIMEvent {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]domain.SCIMEvent, 0, s.size)
	start := 0
	if s.size == s.cap {
		start = s.head
	}
	for i := 0; i < s.size; i++ {
		out = append(out, s.buf[(start+i)%s.cap])
	}
	return out
}
