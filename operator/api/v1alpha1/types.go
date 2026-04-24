// Package v1alpha1 defines the Furnace CRD types.
//
// FurnaceUser and FurnaceGroup are reconciled by the operator to
// Furnace state via the SCIM 2.0 API (POST/PUT/DELETE /scim/v2/Users
// and /scim/v2/Groups).
package v1alpha1

import metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

// FurnaceUserSpec defines the desired user state.
type FurnaceUserSpec struct {
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

// FurnaceUserStatus reflects the observed state of the user in Furnace.
type FurnaceUserStatus struct {
	// FurnaceID is the ID assigned to the user in Furnace.
	// +optional
	FurnaceID string `json:"furnaceId,omitempty"`
	// Conditions summarise the reconciliation state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Email",type="string",JSONPath=".spec.email"
// +kubebuilder:printcolumn:name="Active",type="boolean",JSONPath=".spec.active"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FurnaceUser is the Schema for the furnaceusers API.
type FurnaceUser struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FurnaceUserSpec   `json:"spec,omitempty"`
	Status FurnaceUserStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FurnaceUserList contains a list of FurnaceUser.
type FurnaceUserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FurnaceUser `json:"items"`
}

// FurnaceGroupSpec defines the desired group state.
type FurnaceGroupSpec struct {
	// Name is the machine-readable group name.
	Name string `json:"name"`
	// DisplayName is the human-readable display name.
	// +optional
	DisplayName string `json:"displayName,omitempty"`
}

// FurnaceGroupStatus reflects the observed state of the group in Furnace.
type FurnaceGroupStatus struct {
	// FurnaceID is the ID assigned to the group in Furnace.
	// +optional
	FurnaceID string `json:"furnaceId,omitempty"`
	// Conditions summarise the reconciliation state.
	// +optional
	Conditions []metav1.Condition `json:"conditions,omitempty"`
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:printcolumn:name="Name",type="string",JSONPath=".spec.name"
// +kubebuilder:printcolumn:name="Age",type="date",JSONPath=".metadata.creationTimestamp"

// FurnaceGroup is the Schema for the furnacegroups API.
type FurnaceGroup struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   FurnaceGroupSpec   `json:"spec,omitempty"`
	Status FurnaceGroupStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// FurnaceGroupList contains a list of FurnaceGroup.
type FurnaceGroupList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []FurnaceGroup `json:"items"`
}
