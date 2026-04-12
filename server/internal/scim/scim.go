// Package scim implements a SCIM 2.0 server (RFC 7643, RFC 7644) backed by the
// existing UserStore and GroupStore. It is mounted at /scim/v2 on the HTTP API
// server (:8025).
package scim

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/mux"

	"authpilot/server/internal/domain"
	"authpilot/server/internal/store"
)

// RouterDeps are the dependencies required by the SCIM router.
type RouterDeps struct {
	Users  store.UserStore
	Groups store.GroupStore
}

// NewRouter returns an http.Handler that serves all SCIM 2.0 endpoints under
// the prefix /scim/v2. The caller is responsible for mounting it at that path.
func NewRouter(dep RouterDeps) http.Handler {
	r := mux.NewRouter()

	r.HandleFunc("/scim/v2/ServiceProviderConfig", serviceProviderConfigHandler).Methods(http.MethodGet)
	r.HandleFunc("/scim/v2/Schemas", schemasHandler).Methods(http.MethodGet)
	r.HandleFunc("/scim/v2/Schemas/{id}", schemaByIDHandler).Methods(http.MethodGet)

	r.HandleFunc("/scim/v2/Users", listUsersHandler(dep.Users)).Methods(http.MethodGet)
	r.HandleFunc("/scim/v2/Users", createUserHandler(dep.Users)).Methods(http.MethodPost)
	r.HandleFunc("/scim/v2/Users/{id}", getUserHandler(dep.Users)).Methods(http.MethodGet)
	r.HandleFunc("/scim/v2/Users/{id}", replaceUserHandler(dep.Users)).Methods(http.MethodPut)
	r.HandleFunc("/scim/v2/Users/{id}", patchUserHandler(dep.Users)).Methods(http.MethodPatch)
	r.HandleFunc("/scim/v2/Users/{id}", deleteUserHandler(dep.Users)).Methods(http.MethodDelete)

	r.HandleFunc("/scim/v2/Groups", listGroupsHandler(dep.Groups, dep.Users)).Methods(http.MethodGet)
	r.HandleFunc("/scim/v2/Groups", createGroupHandler(dep.Groups)).Methods(http.MethodPost)
	r.HandleFunc("/scim/v2/Groups/{id}", getGroupHandler(dep.Groups, dep.Users)).Methods(http.MethodGet)
	r.HandleFunc("/scim/v2/Groups/{id}", replaceGroupHandler(dep.Groups, dep.Users)).Methods(http.MethodPut)
	r.HandleFunc("/scim/v2/Groups/{id}", patchGroupHandler(dep.Groups, dep.Users)).Methods(http.MethodPatch)
	r.HandleFunc("/scim/v2/Groups/{id}", deleteGroupHandler(dep.Groups)).Methods(http.MethodDelete)

	return r
}

// ---------------------------------------------------------------------------
// SCIM resource types
// ---------------------------------------------------------------------------

const (
	schemaUser  = "urn:ietf:params:scim:schemas:core:2.0:User"
	schemaGroup = "urn:ietf:params:scim:schemas:core:2.0:Group"
	schemaSPC   = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
	listSchema  = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	errorSchema = "urn:ietf:params:scim:api:messages:2.0:Error"
	patchSchema = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
)

type meta struct {
	ResourceType string `json:"resourceType"`
	Created      string `json:"created"`
	LastModified string `json:"lastModified"`
	Location     string `json:"location"`
}

type scimUser struct {
	Schemas     []string   `json:"schemas"`
	ID          string     `json:"id"`
	ExternalID  string     `json:"externalId,omitempty"`
	UserName    string     `json:"userName"`
	DisplayName string     `json:"displayName,omitempty"`
	Active      bool       `json:"active"`
	Emails      []scimAttr `json:"emails,omitempty"`
	PhoneNums   []scimAttr `json:"phoneNumbers,omitempty"`
	Groups      []scimRef  `json:"groups,omitempty"`
	Meta        meta       `json:"meta"`
}

type scimGroup struct {
	Schemas     []string  `json:"schemas"`
	ID          string    `json:"id"`
	DisplayName string    `json:"displayName"`
	Members     []scimRef `json:"members,omitempty"`
	Meta        meta      `json:"meta"`
}

type scimAttr struct {
	Value   string `json:"value"`
	Primary bool   `json:"primary,omitempty"`
	Type    string `json:"type,omitempty"`
}

type scimRef struct {
	Value   string `json:"value"`
	Display string `json:"display,omitempty"`
	Ref     string `json:"$ref,omitempty"`
}

type listResponse struct {
	Schemas      []string `json:"schemas"`
	TotalResults int      `json:"totalResults"`
	StartIndex   int      `json:"startIndex"`
	ItemsPerPage int      `json:"itemsPerPage"`
	Resources    []any    `json:"Resources"`
}

type scimError struct {
	Schemas  []string `json:"schemas"`
	Status   string   `json:"status"`
	Detail   string   `json:"detail"`
	ScimType string   `json:"scimType,omitempty"`
}

// patchOp is the body of a PATCH request.
type patchOp struct {
	Schemas    []string    `json:"schemas"`
	Operations []patchItem `json:"Operations"`
}

type patchItem struct {
	Op    string `json:"op"`
	Path  string `json:"path,omitempty"`
	Value any    `json:"value"`
}

// userInput is the subset of SCIM User fields we accept on create/replace.
type userInput struct {
	UserName    string     `json:"userName"`
	DisplayName string     `json:"displayName"`
	ExternalID  string     `json:"externalId"`
	Active      *bool      `json:"active"`
	Emails      []scimAttr `json:"emails"`
	PhoneNums   []scimAttr `json:"phoneNumbers"`
}

// groupInput is the subset of SCIM Group fields we accept on create/replace.
type groupInput struct {
	DisplayName string    `json:"displayName"`
	Members     []scimRef `json:"members"`
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func writeScimJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/scim+json")
	w.WriteHeader(status)
	_, _ = w.Write(mustJSON(v))
}

func writeScimError(w http.ResponseWriter, status int, detail string, scimType string) {
	writeScimJSON(w, status, scimError{
		Schemas:  []string{errorSchema},
		Status:   fmt.Sprintf("%d", status),
		Detail:   detail,
		ScimType: scimType,
	})
}

func mustJSON(v any) []byte {
	b, _ := json.Marshal(v)
	return b
}

func userToSCIM(u domain.User, groups []domain.Group) scimUser {
	emails := []scimAttr{{Value: u.Email, Primary: true, Type: "work"}}
	var phones []scimAttr
	if u.PhoneNumber != "" {
		phones = []scimAttr{{Value: u.PhoneNumber, Primary: true, Type: "work"}}
	}

	// Build group refs for groups the user belongs to.
	var groupRefs []scimRef
	for _, g := range groups {
		for _, mid := range g.MemberIDs {
			if mid == u.ID {
				groupRefs = append(groupRefs, scimRef{
					Value:   g.ID,
					Display: g.DisplayName,
					Ref:     "../Groups/" + g.ID,
				})
				break
			}
		}
	}

	ts := u.CreatedAt.UTC().Format(time.RFC3339)
	return scimUser{
		Schemas:     []string{schemaUser},
		ID:          u.ID,
		UserName:    u.Email,
		DisplayName: u.DisplayName,
		Active:      u.Active,
		Emails:      emails,
		PhoneNums:   phones,
		Groups:      groupRefs,
		Meta: meta{
			ResourceType: "User",
			Created:      ts,
			LastModified: ts,
			Location:     "/scim/v2/Users/" + u.ID,
		},
	}
}

func groupToSCIM(g domain.Group, users []domain.User) scimGroup {
	// Build user ref list from member IDs.
	memberSet := make(map[string]struct{}, len(g.MemberIDs))
	for _, id := range g.MemberIDs {
		memberSet[id] = struct{}{}
	}
	var members []scimRef
	for _, u := range users {
		if _, ok := memberSet[u.ID]; ok {
			members = append(members, scimRef{
				Value:   u.ID,
				Display: u.DisplayName,
				Ref:     "../Users/" + u.ID,
			})
		}
	}

	ts := g.CreatedAt.UTC().Format(time.RFC3339)
	return scimGroup{
		Schemas:     []string{schemaGroup},
		ID:          g.ID,
		DisplayName: g.DisplayName,
		Members:     members,
		Meta: meta{
			ResourceType: "Group",
			Created:      ts,
			LastModified: ts,
			Location:     "/scim/v2/Groups/" + g.ID,
		},
	}
}

// primaryEmail returns the first email marked primary, or the first email overall.
func primaryEmail(emails []scimAttr) string {
	for _, e := range emails {
		if e.Primary {
			return e.Value
		}
	}
	if len(emails) > 0 {
		return emails[0].Value
	}
	return ""
}

// primaryPhone returns the first phone marked primary, or the first phone overall.
func primaryPhone(phones []scimAttr) string {
	for _, p := range phones {
		if p.Primary {
			return p.Value
		}
	}
	if len(phones) > 0 {
		return phones[0].Value
	}
	return ""
}

// matchesFilter does a simple attribute filter for ?filter=userName eq "..."
// Only eq on userName and displayName are supported; all other filters pass.
func matchesFilter(u scimUser, filter string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return true
	}
	// parse: <attr> eq "<value>"
	parts := strings.SplitN(filter, " ", 3)
	if len(parts) != 3 || strings.ToLower(parts[1]) != "eq" {
		return true // unsupported filter — return all
	}
	attr := strings.ToLower(parts[0])
	val := strings.Trim(parts[2], `"`)
	switch attr {
	case "username":
		return strings.EqualFold(u.UserName, val)
	case "displayname":
		return strings.EqualFold(u.DisplayName, val)
	default:
		return true
	}
}

func newUserID() string {
	return fmt.Sprintf("usr_%d", time.Now().UnixNano())
}

func newGroupID() string {
	return fmt.Sprintf("grp_%d", time.Now().UnixNano())
}

// ---------------------------------------------------------------------------
// ServiceProviderConfig
// ---------------------------------------------------------------------------

func serviceProviderConfigHandler(w http.ResponseWriter, _ *http.Request) {
	writeScimJSON(w, http.StatusOK, map[string]any{
		"schemas": []string{schemaSPC},
		"documentationUri": "https://tools.ietf.org/html/rfc7643",
		"patch":            map[string]any{"supported": true},
		"bulk":             map[string]any{"supported": false, "maxOperations": 0, "maxPayloadSize": 0},
		"filter":           map[string]any{"supported": true, "maxResults": 200},
		"changePassword":   map[string]any{"supported": false},
		"sort":             map[string]any{"supported": false},
		"etag":             map[string]any{"supported": false},
		"authenticationSchemes": []map[string]any{
			{
				"name":        "OAuth Bearer Token",
				"description": "Authentication scheme using the OAuth Bearer Token standard",
				"specUri":     "https://tools.ietf.org/html/rfc6750",
				"type":        "oauthbearertoken",
				"primary":     true,
			},
		},
		"meta": map[string]any{
			"resourceType": "ServiceProviderConfig",
			"location":     "/scim/v2/ServiceProviderConfig",
		},
	})
}

// ---------------------------------------------------------------------------
// Schemas
// ---------------------------------------------------------------------------

var userSchema = map[string]any{
	"id":          schemaUser,
	"name":        "User",
	"description": "User Account",
	"attributes": []map[string]any{
		{"name": "userName", "type": "string", "required": true, "uniqueness": "server"},
		{"name": "displayName", "type": "string", "required": false},
		{"name": "active", "type": "boolean", "required": false},
		{"name": "emails", "type": "complex", "multiValued": true},
		{"name": "phoneNumbers", "type": "complex", "multiValued": true},
		{"name": "groups", "type": "complex", "multiValued": true, "mutability": "readOnly"},
	},
	"meta": map[string]any{"resourceType": "Schema", "location": "/scim/v2/Schemas/" + schemaUser},
}

var groupSchema = map[string]any{
	"id":          schemaGroup,
	"name":        "Group",
	"description": "Group",
	"attributes": []map[string]any{
		{"name": "displayName", "type": "string", "required": true},
		{"name": "members", "type": "complex", "multiValued": true},
	},
	"meta": map[string]any{"resourceType": "Schema", "location": "/scim/v2/Schemas/" + schemaGroup},
}

func schemasHandler(w http.ResponseWriter, _ *http.Request) {
	writeScimJSON(w, http.StatusOK, listResponse{
		Schemas:      []string{listSchema},
		TotalResults: 2,
		StartIndex:   1,
		ItemsPerPage: 2,
		Resources:    []any{userSchema, groupSchema},
	})
}

func schemaByIDHandler(w http.ResponseWriter, r *http.Request) {
	id := mux.Vars(r)["id"]
	switch id {
	case schemaUser:
		writeScimJSON(w, http.StatusOK, userSchema)
	case schemaGroup:
		writeScimJSON(w, http.StatusOK, groupSchema)
	default:
		writeScimError(w, http.StatusNotFound, "schema not found", "")
	}
}

// ---------------------------------------------------------------------------
// Users
// ---------------------------------------------------------------------------

func listUsersHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all, err := users.List()
		if err != nil {
			writeScimError(w, http.StatusInternalServerError, err.Error(), "")
			return
		}
		// Resolve groups for membership refs.
		filter := r.URL.Query().Get("filter")
		var resources []any
		for _, u := range all {
			su := userToSCIM(u, nil)
			if matchesFilter(su, filter) {
				resources = append(resources, su)
			}
		}
		if resources == nil {
			resources = []any{}
		}
		writeScimJSON(w, http.StatusOK, listResponse{
			Schemas:      []string{listSchema},
			TotalResults: len(resources),
			StartIndex:   1,
			ItemsPerPage: len(resources),
			Resources:    resources,
		})
	}
}

func createUserHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input userInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeScimError(w, http.StatusBadRequest, "invalid JSON body", "invalidValue")
			return
		}
		if input.UserName == "" {
			writeScimError(w, http.StatusBadRequest, "userName is required", "invalidValue")
			return
		}
		// Enforce userName uniqueness (RFC 7644 §3.3 — server MUST return 409
		// if the userName is already in use).
		if existing, _ := users.List(); existing != nil {
			for _, u := range existing {
				if u.Email == input.UserName {
					writeScimError(w, http.StatusConflict, "userName already in use", "uniqueness")
					return
				}
			}
		}
		email := primaryEmail(input.Emails)
		if email == "" {
			email = input.UserName
		}
		active := true
		if input.Active != nil {
			active = *input.Active
		}
		u := domain.User{
			ID:          newUserID(),
			Email:       email,
			DisplayName: input.DisplayName,
			PhoneNumber: primaryPhone(input.PhoneNums),
			Active:      active,
			CreatedAt:   time.Now().UTC(),
		}
		created, err := users.Create(u)
		if err != nil {
			writeScimError(w, http.StatusConflict, err.Error(), "uniqueness")
			return
		}
		writeScimJSON(w, http.StatusCreated, userToSCIM(created, nil))
	}
}

func getUserHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		u, err := users.GetByID(id)
		if err != nil {
			writeScimError(w, http.StatusNotFound, "user not found", "")
			return
		}
		writeScimJSON(w, http.StatusOK, userToSCIM(u, nil))
	}
}

func replaceUserHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		existing, err := users.GetByID(id)
		if err != nil {
			writeScimError(w, http.StatusNotFound, "user not found", "")
			return
		}
		var input userInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeScimError(w, http.StatusBadRequest, "invalid JSON body", "invalidValue")
			return
		}
		email := primaryEmail(input.Emails)
		if email == "" {
			email = input.UserName
		}
		if email == "" {
			email = existing.Email
		}
		existing.Email = email
		existing.DisplayName = input.DisplayName
		existing.PhoneNumber = primaryPhone(input.PhoneNums)
		if input.Active != nil {
			existing.Active = *input.Active
		}
		updated, err := users.Update(existing)
		if err != nil {
			writeScimError(w, http.StatusInternalServerError, err.Error(), "")
			return
		}
		writeScimJSON(w, http.StatusOK, userToSCIM(updated, nil))
	}
}

func patchUserHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		u, err := users.GetByID(id)
		if err != nil {
			writeScimError(w, http.StatusNotFound, "user not found", "")
			return
		}
		var op patchOp
		if err := json.NewDecoder(r.Body).Decode(&op); err != nil {
			writeScimError(w, http.StatusBadRequest, "invalid JSON body", "invalidValue")
			return
		}
		for _, item := range op.Operations {
			switch strings.ToLower(item.Op) {
			case "replace", "add":
				applyUserPatch(&u, item.Path, item.Value)
			case "remove":
				// remove is a no-op for the fields we support
			}
		}
		updated, err := users.Update(u)
		if err != nil {
			writeScimError(w, http.StatusInternalServerError, err.Error(), "")
			return
		}
		writeScimJSON(w, http.StatusOK, userToSCIM(updated, nil))
	}
}

func applyUserPatch(u *domain.User, path string, value any) {
	// value may arrive as a map or string; normalise to string where needed.
	strVal := func() string {
		if s, ok := value.(string); ok {
			return s
		}
		b, _ := json.Marshal(value)
		return strings.Trim(string(b), `"`)
	}
	switch strings.ToLower(path) {
	case "displayname":
		u.DisplayName = strVal()
	case "username", "emails[type eq \"work\"].value":
		u.Email = strVal()
	case "phonenumbers[type eq \"work\"].value", "phonenumbers":
		u.PhoneNumber = strVal()
	case "active":
		switch v := value.(type) {
		case bool:
			u.Active = v
		case string:
			u.Active = strings.EqualFold(v, "true")
		}
	case "":
		// value is a map of field→value
		if m, ok := value.(map[string]any); ok {
			for k, v := range m {
				applyUserPatch(u, k, v)
			}
		}
	}
}

func deleteUserHandler(users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		if err := users.Delete(id); err != nil {
			writeScimError(w, http.StatusNotFound, "user not found", "")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ---------------------------------------------------------------------------
// Groups
// ---------------------------------------------------------------------------

func listGroupsHandler(groups store.GroupStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		all, err := groups.List()
		if err != nil {
			writeScimError(w, http.StatusInternalServerError, err.Error(), "")
			return
		}
		userList, _ := users.List()
		var resources []any
		for _, g := range all {
			resources = append(resources, groupToSCIM(g, userList))
		}
		if resources == nil {
			resources = []any{}
		}
		writeScimJSON(w, http.StatusOK, listResponse{
			Schemas:      []string{listSchema},
			TotalResults: len(resources),
			StartIndex:   1,
			ItemsPerPage: len(resources),
			Resources:    resources,
		})
	}
}

func createGroupHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var input groupInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeScimError(w, http.StatusBadRequest, "invalid JSON body", "invalidValue")
			return
		}
		if input.DisplayName == "" {
			writeScimError(w, http.StatusBadRequest, "displayName is required", "invalidValue")
			return
		}
		memberIDs := make([]string, 0, len(input.Members))
		for _, m := range input.Members {
			memberIDs = append(memberIDs, m.Value)
		}
		g := domain.Group{
			ID:          newGroupID(),
			Name:        strings.ToLower(strings.ReplaceAll(input.DisplayName, " ", "-")),
			DisplayName: input.DisplayName,
			MemberIDs:   memberIDs,
			CreatedAt:   time.Now().UTC(),
		}
		created, err := groups.Create(g)
		if err != nil {
			writeScimError(w, http.StatusConflict, err.Error(), "uniqueness")
			return
		}
		writeScimJSON(w, http.StatusCreated, groupToSCIM(created, nil))
	}
}

func getGroupHandler(groups store.GroupStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		g, err := groups.GetByID(id)
		if err != nil {
			writeScimError(w, http.StatusNotFound, "group not found", "")
			return
		}
		userList, _ := users.List()
		writeScimJSON(w, http.StatusOK, groupToSCIM(g, userList))
	}
}

func replaceGroupHandler(groups store.GroupStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		existing, err := groups.GetByID(id)
		if err != nil {
			writeScimError(w, http.StatusNotFound, "group not found", "")
			return
		}
		var input groupInput
		if err := json.NewDecoder(r.Body).Decode(&input); err != nil {
			writeScimError(w, http.StatusBadRequest, "invalid JSON body", "invalidValue")
			return
		}
		if input.DisplayName != "" {
			existing.DisplayName = input.DisplayName
			existing.Name = strings.ToLower(strings.ReplaceAll(input.DisplayName, " ", "-"))
		}
		memberIDs := make([]string, 0, len(input.Members))
		for _, m := range input.Members {
			memberIDs = append(memberIDs, m.Value)
		}
		existing.MemberIDs = memberIDs
		updated, err := groups.Update(existing)
		if err != nil {
			writeScimError(w, http.StatusInternalServerError, err.Error(), "")
			return
		}
		userList, _ := users.List()
		writeScimJSON(w, http.StatusOK, groupToSCIM(updated, userList))
	}
}

func patchGroupHandler(groups store.GroupStore, users store.UserStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		g, err := groups.GetByID(id)
		if err != nil {
			writeScimError(w, http.StatusNotFound, "group not found", "")
			return
		}
		var op patchOp
		if err := json.NewDecoder(r.Body).Decode(&op); err != nil {
			writeScimError(w, http.StatusBadRequest, "invalid JSON body", "invalidValue")
			return
		}
		for _, item := range op.Operations {
			switch strings.ToLower(item.Op) {
			case "add":
				applyGroupPatchAdd(&g, item.Path, item.Value)
			case "remove":
				applyGroupPatchRemove(&g, item.Path, item.Value)
			case "replace":
				applyGroupPatch(&g, item.Path, item.Value)
			}
		}
		updated, err := groups.Update(g)
		if err != nil {
			writeScimError(w, http.StatusInternalServerError, err.Error(), "")
			return
		}
		userList, _ := users.List()
		writeScimJSON(w, http.StatusOK, groupToSCIM(updated, userList))
	}
}

func applyGroupPatch(g *domain.Group, path string, value any) {
	switch strings.ToLower(path) {
	case "displayname":
		if s, ok := value.(string); ok {
			g.DisplayName = s
			g.Name = strings.ToLower(strings.ReplaceAll(s, " ", "-"))
		}
	case "members":
		g.MemberIDs = extractMemberIDs(value)
	case "":
		if m, ok := value.(map[string]any); ok {
			for k, v := range m {
				applyGroupPatch(g, k, v)
			}
		}
	}
}

func applyGroupPatchAdd(g *domain.Group, path string, value any) {
	if strings.ToLower(path) != "members" {
		applyGroupPatch(g, path, value)
		return
	}
	existing := make(map[string]struct{}, len(g.MemberIDs))
	for _, id := range g.MemberIDs {
		existing[id] = struct{}{}
	}
	for _, id := range extractMemberIDs(value) {
		if _, ok := existing[id]; !ok {
			g.MemberIDs = append(g.MemberIDs, id)
			existing[id] = struct{}{}
		}
	}
}

func applyGroupPatchRemove(g *domain.Group, path string, value any) {
	if strings.ToLower(path) != "members" {
		return
	}
	remove := make(map[string]struct{})
	for _, id := range extractMemberIDs(value) {
		remove[id] = struct{}{}
	}
	kept := g.MemberIDs[:0]
	for _, id := range g.MemberIDs {
		if _, ok := remove[id]; !ok {
			kept = append(kept, id)
		}
	}
	g.MemberIDs = kept
}

// extractMemberIDs coerces value (array of {value:id} objects or plain strings)
// into a slice of member ID strings.
func extractMemberIDs(value any) []string {
	var ids []string
	switch v := value.(type) {
	case []any:
		for _, item := range v {
			switch m := item.(type) {
			case map[string]any:
				if id, ok := m["value"].(string); ok {
					ids = append(ids, id)
				}
			case string:
				ids = append(ids, m)
			}
		}
	case string:
		ids = append(ids, v)
	}
	return ids
}

func deleteGroupHandler(groups store.GroupStore) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := mux.Vars(r)["id"]
		if err := groups.Delete(id); err != nil {
			writeScimError(w, http.StatusNotFound, "group not found", "")
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}
