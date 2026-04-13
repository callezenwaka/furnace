package scimclient

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"authpilot/server/internal/domain"
	"authpilot/server/internal/store/memory"
)

func waitForEvent(t *testing.T, store *memory.SCIMEventStore, timeout time.Duration) domain.SCIMEvent {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if list := store.List(); len(list) > 0 {
			return list[len(list)-1]
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("timed out waiting for SCIM event")
	return domain.SCIMEvent{}
}

func TestUserCreated_PostsToTarget(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody map[string]any

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	events := memory.NewSCIMEventStore(100)
	c := New(srv.URL+"/scim/v2", events)
	user := domain.User{ID: "u1", Email: "a@b.com", DisplayName: "Alice", Active: true}
	c.UserCreated(user)

	ev := waitForEvent(t, events, time.Second)

	if gotMethod != http.MethodPost {
		t.Fatalf("expected POST, got %s", gotMethod)
	}
	if gotPath != "/scim/v2/Users" {
		t.Fatalf("expected /scim/v2/Users, got %s", gotPath)
	}
	if ev.ResponseStatus != http.StatusCreated {
		t.Fatalf("expected status 201, got %d", ev.ResponseStatus)
	}
	if gotBody["userName"] != "a@b.com" {
		t.Fatalf("expected userName=a@b.com, got %v", gotBody["userName"])
	}
}

func TestUserUpdated_PutsToTarget(t *testing.T) {
	var gotMethod, gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	events := memory.NewSCIMEventStore(100)
	c := New(srv.URL+"/scim/v2", events)
	c.UserUpdated(domain.User{ID: "u1", Email: "a@b.com", Active: true})

	waitForEvent(t, events, time.Second)

	if gotMethod != http.MethodPut {
		t.Fatalf("expected PUT, got %s", gotMethod)
	}
	if gotPath != "/scim/v2/Users/u1" {
		t.Fatalf("expected /scim/v2/Users/u1, got %s", gotPath)
	}
}

func TestUserDeleted_DeletesAtTarget(t *testing.T) {
	var gotMethod, gotPath string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	events := memory.NewSCIMEventStore(100)
	c := New(srv.URL+"/scim/v2", events)
	c.UserDeleted("u1")

	waitForEvent(t, events, time.Second)

	if gotMethod != http.MethodDelete {
		t.Fatalf("expected DELETE, got %s", gotMethod)
	}
	if gotPath != "/scim/v2/Users/u1" {
		t.Fatalf("expected /scim/v2/Users/u1, got %s", gotPath)
	}
}

func TestPushFailure_RecordedAsError_DoesNotPanic(t *testing.T) {
	// Point at a URL that will refuse connections.
	events := memory.NewSCIMEventStore(100)
	c := New("http://127.0.0.1:1", events) // port 1 is always refused
	c.UserCreated(domain.User{ID: "u1", Email: "a@b.com", Active: true})

	ev := waitForEvent(t, events, 3*time.Second)
	if ev.Error == "" {
		t.Fatal("expected error to be recorded for unreachable target")
	}
	if ev.ResponseStatus != 0 {
		t.Fatalf("expected response_status=0 for connection failure, got %d", ev.ResponseStatus)
	}
}

func TestToSCIMUser_Fields(t *testing.T) {
	u := domain.User{
		ID:          "u1",
		Email:       "a@b.com",
		DisplayName: "Alice",
		Groups:      []string{"eng", "admin"},
		Active:      true,
	}
	su := toSCIMUser(u)

	if su.UserName != "a@b.com" {
		t.Fatalf("expected userName=a@b.com, got %s", su.UserName)
	}
	if su.DisplayName != "Alice" {
		t.Fatalf("expected displayName=Alice, got %s", su.DisplayName)
	}
	if len(su.Groups) != 2 {
		t.Fatalf("expected 2 groups, got %d", len(su.Groups))
	}
	if len(su.Emails) != 1 || !su.Emails[0].Primary {
		t.Fatal("expected one primary email")
	}
	if su.Schemas[0] != "urn:ietf:params:scim:schemas:core:2.0:User" {
		t.Fatalf("unexpected schema: %s", su.Schemas[0])
	}
}
