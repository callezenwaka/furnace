// Package v1alpha1 defines the Authpilot CRD types.
//
// AuthpilotUser and AuthpilotGroup are reconciled by the operator to
// Authpilot state via the SCIM 2.0 API (POST/PUT/DELETE /scim/v2/Users
// and /scim/v2/Groups).
package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// AuthpilotUserSpec defines the desired user state.
type AuthpilotUserSpec struct {
	// Email is the user's email address, used as the SCIM userName.
	Email string `json:"email"`
	// DisplayName is the human-readable display name.
	// +optional
	DisplayName string `json:"displayName,omitempty"`
	// Groups lists the group IDs this user belongs to.
	// +optional
	Groups []string `json:"groups,omitempty"`
	// MFAMethod controls which MFA flow is triggered. One of: none, totp,
	// sms, push, magic_link, webauthn.
	// +optional
	MFAMethod string `json:"mfaMethod,omitempty"`
	// Active controls whether the user can authenticate. Defaults to true.
	// +optional
	// +kubebuilder:default=true
	Active bool `json:"active"`
}

// AuthpilotUserStatus reflects the observed state of the user in Authpilot.
type AuthpilotUserStatus struct {
	// AuthpilotID is the ID assigned to the user in Authpilot.
	// +optional
	AuthpilotID string `json:"authpilotId,omitempty"`
	// Conditions summarise the reconciliation state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Email",type="string",JSONPath=".spec.email"
// +kubebuilder:printcolumn:name="Active",type="boolean",JSONPath=".spec.active"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// AuthpilotUser is the Schema for the authpilotusers API.
type AuthpilotUser struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthpilotUserSpec   `json:"spec,omitempty"`
	Status AuthpilotUserStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AuthpilotUserList contains a list of AuthpilotUser.
type AuthpilotUserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuthpilotUser `json:"items"`
}

// AuthpilotGroupSpec defines the desired group state.
type AuthpilotGroupSpec struct {
	// Name is the machine-readable group name.
	Name string `json:"name"`
	// DisplayName is the human-readable display name.
	// +optional
	DisplayName string `json:"displayName,omitempty"`
}

// AuthpilotGroupStatus reflects the observed state of the group in Authpilot.
type AuthpilotGroupStatus struct {
	// AuthpilotID is the ID assigned to the group in Authpilot.
	// +optional
	AuthpilotID string `json:"authpilotId,omitempty"`
	// Conditions summarise the reconciliation state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Name",type="string",JSONPath=".spec.name"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// AuthpilotGroup is the Schema for the authpilotgroups API.
type AuthpilotGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   AuthpilotGroupSpec   `json:"spec,omitempty"`
	Status AuthpilotGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// AuthpilotGroupList contains a list of AuthpilotGroup.
type AuthpilotGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []AuthpilotGroup `json:"items"`
}
