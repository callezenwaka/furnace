package httpapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"time"
)

type contextKey string

const requestIDKey contextKey = "request_id"

// requestIDMiddleware generates a request ID for every incoming request and
// stores it on the context. The ID is also echoed back in X-Request-ID.
func requestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = newRequestID()
		}
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		w.Header().Set("X-Request-ID", id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func getRequestID(r *http.Request) string {
	if id, ok := r.Context().Value(requestIDKey).(string); ok {
		return id
	}
	return ""
}

func newRequestID() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return "req_" + hex.EncodeToString(b)
}

// --- Rate limiting (token bucket per IP) ---

// RateLimiter is a per-IP token bucket rate limiter.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	limit    int           // max tokens
	refill   time.Duration // how often one token is added back
}

type bucket struct {
	tokens   int
	lastSeen time.Time
}

// NewRateLimiter creates a limiter allowing limit requests per window duration.
// e.g. NewRateLimiter(100, time.Minute) → 100 req/min per IP.
func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		buckets: make(map[string]*bucket),
		limit:   limit,
		refill:  window / time.Duration(limit),
	}
	// Background goroutine evicts stale buckets every minute.
	go func() {
		ticker := time.NewTicker(time.Minute)
		for range ticker.C {
			rl.evict()
		}
	}()
	return rl
}

func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[ip]
	if !ok {
		rl.buckets[ip] = &bucket{tokens: rl.limit - 1, lastSeen: now}
		return true
	}

	// Refill tokens based on elapsed time.
	elapsed := now.Sub(b.lastSeen)
	refilled := int(elapsed / rl.refill)
	if refilled > 0 {
		b.tokens += refilled
		if b.tokens > rl.limit {
			b.tokens = rl.limit
		}
		b.lastSeen = now
	}

	if b.tokens <= 0 {
		return false
	}
	b.tokens--
	return true
}

func (rl *RateLimiter) evict() {
	rl.mu.Lock()
	defer rl.mu.Unlock()
	cutoff := time.Now().Add(-5 * time.Minute)
	for ip, b := range rl.buckets {
		if b.lastSeen.Before(cutoff) {
			delete(rl.buckets, ip)
		}
	}
}

// rateLimitMiddleware returns a middleware that enforces the given RateLimiter.
// Uses X-Forwarded-For if present, otherwise RemoteAddr.
func rateLimitMiddleware(rl *RateLimiter) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := clientIP(r)
			if !rl.allow(ip) {
				writeAPIError(w, r, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, slow down", true)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if idx := strings.IndexByte(xff, ','); idx >= 0 {
			return strings.TrimSpace(xff[:idx])
		}
		return strings.TrimSpace(xff)
	}
	if idx := strings.LastIndexByte(r.RemoteAddr, ':'); idx >= 0 {
		return r.RemoteAddr[:idx]
	}
	return r.RemoteAddr
}

// --- Idempotency key caching ---

// idempotencyStore caches responses for POST requests that carry an Idempotency-Key.
type idempotencyStore struct {
	mu      sync.Mutex
	entries map[string]*idempotencyEntry
	ttl     time.Duration
}

type idempotencyEntry struct {
	status  int
	headers http.Header
	body    []byte
	created time.Time
}

// newIdempotencyStore creates a store with the given TTL for cached responses.
func newIdempotencyStore(ttl time.Duration) *idempotencyStore {
	s := &idempotencyStore{
		entries: make(map[string]*idempotencyEntry),
		ttl:     ttl,
	}
	go func() {
		ticker := time.NewTicker(time.Minute)
		for range ticker.C {
			s.evict()
		}
	}()
	return s
}

func (s *idempotencyStore) get(key string) (*idempotencyEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entries[key]
	if !ok || time.Since(e.created) > s.ttl {
		return nil, false
	}
	return e, true
}

func (s *idempotencyStore) set(key string, e *idempotencyEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[key] = e
}

func (s *idempotencyStore) evict() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, e := range s.entries {
		if time.Since(e.created) > s.ttl {
			delete(s.entries, k)
		}
	}
}

// idempotencyMiddleware intercepts POST requests with an Idempotency-Key header.
// On first request: execute normally, cache the response.
// On repeat request (same key within TTL): return cached response with Idempotent-Replayed: true.
func idempotencyMiddleware(store *idempotencyStore) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			cacheKey := r.Method + ":" + r.URL.Path + ":" + key

			// Return cached response if available.
			if entry, ok := store.get(cacheKey); ok {
				for k, vals := range entry.headers {
					for _, v := range vals {
						w.Header().Add(k, v)
					}
				}
				w.Header().Set("Idempotent-Replayed", "true")
				w.WriteHeader(entry.status)
				_, _ = w.Write(entry.body)
				return
			}

			// Capture the response.
			rec := httptest.NewRecorder()
			next.ServeHTTP(rec, r)

			entry := &idempotencyEntry{
				status:  rec.Code,
				headers: rec.Header().Clone(),
				body:    bytes.Clone(rec.Body.Bytes()),
				created: time.Now(),
			}
			store.set(cacheKey, entry)

			// Write the real response.
			for k, vals := range rec.Header() {
				for _, v := range vals {
					w.Header().Add(k, v)
				}
			}
			w.WriteHeader(rec.Code)
			_, _ = w.Write(rec.Body.Bytes())
		})
	}
}

// apiKeyMiddleware protects /api/v1/* routes when a key is configured.
// If apiKey is empty the middleware is a no-op (local dev mode).
func apiKeyMiddleware(apiKey string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if apiKey == "" {
				next.ServeHTTP(w, r)
				return
			}
			key := r.Header.Get("X-Authpilot-Api-Key")
			if key == "" {
				auth := r.Header.Get("Authorization")
				if strings.HasPrefix(auth, "Bearer ") {
					key = strings.TrimPrefix(auth, "Bearer ")
				}
			}
			if key != apiKey {
				writeAPIError(w, r, http.StatusUnauthorized, "UNAUTHORIZED", "missing or invalid api key", false)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
