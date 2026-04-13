// Package scimclient implements an outbound SCIM 2.0 push client.
//
// When Authpilot runs in SCIM client mode (AUTHPILOT_SCIM_MODE=client) it
// mirrors every user create/update/delete to an external SCIM server. Pushes
// are best-effort: failures are logged in the SCIMEventStore but never block
// the management API call that triggered them.
package scimclient

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"authpilot/server/internal/domain"
	"authpilot/server/internal/store"
)

// Client pushes user mutations to a remote SCIM 2.0 target.
type Client struct {
	targetURL string        // base URL, e.g. "https://scim.example.com/scim/v2"
	http      *http.Client
	events    store.SCIMEventStore
}

// New returns a Client configured to push to targetURL.
// events is required; it records every outbound request.
func New(targetURL string, events store.SCIMEventStore) *Client {
	return &Client{
		targetURL: targetURL,
		http:      &http.Client{Timeout: 10 * time.Second},
		events:    events,
	}
}

// UserCreated pushes a SCIM POST /Users request. Non-blocking.
func (c *Client) UserCreated(user domain.User) {
	go c.push(http.MethodPost, c.targetURL+"/Users", toSCIMUser(user))
}

// UserUpdated pushes a SCIM PUT /Users/{id} request. Non-blocking.
func (c *Client) UserUpdated(user domain.User) {
	go c.push(http.MethodPut, c.targetURL+"/Users/"+user.ID, toSCIMUser(user))
}

// UserDeleted pushes a SCIM DELETE /Users/{id} request. Non-blocking.
func (c *Client) UserDeleted(id string) {
	go c.push(http.MethodDelete, c.targetURL+"/Users/"+id, nil)
}

func (c *Client) push(method, url string, body any) {
	event := domain.SCIMEvent{
		Timestamp: time.Now().UTC(),
		Method:    method,
		URL:       url,
	}

	var reqBody []byte
	if body != nil {
		var err error
		reqBody, err = json.Marshal(body)
		if err != nil {
			event.Error = fmt.Sprintf("marshal body: %v", err)
			c.events.Append(event)
			return
		}
		event.RequestBody = string(reqBody)
	}

	req, err := http.NewRequestWithContext(context.Background(), method, url, bytes.NewReader(reqBody))
	if err != nil {
		event.Error = fmt.Sprintf("build request: %v", err)
		c.events.Append(event)
		return
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/scim+json")
	}
	req.Header.Set("Accept", "application/scim+json")

	resp, err := c.http.Do(req)
	if err != nil {
		event.Error = fmt.Sprintf("http: %v", err)
		c.events.Append(event)
		return
	}
	defer resp.Body.Close()

	event.ResponseStatus = resp.StatusCode
	if b, err := io.ReadAll(io.LimitReader(resp.Body, 8*1024)); err == nil {
		event.ResponseBody = string(b)
	}
	c.events.Append(event)
}

// scimUser is the minimal SCIM 2.0 User representation we push.
type scimUser struct {
	Schemas     []string         `json:"schemas"`
	ID          string           `json:"id"`
	UserName    string           `json:"userName"`
	DisplayName string           `json:"displayName,omitempty"`
	Emails      []scimEmail      `json:"emails,omitempty"`
	Groups      []scimGroupRef   `json:"groups,omitempty"`
	Active      bool             `json:"active"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary"`
}

type scimGroupRef struct {
	Value string `json:"value"`
}

func toSCIMUser(u domain.User) scimUser {
	su := scimUser{
		Schemas:     []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		ID:          u.ID,
		UserName:    u.Email,
		DisplayName: u.DisplayName,
		Active:      u.Active,
	}
	if u.Email != "" {
		su.Emails = []scimEmail{{Value: u.Email, Primary: true}}
	}
	for _, g := range u.Groups {
		su.Groups = append(su.Groups, scimGroupRef{Value: g})
	}
	return su
}
