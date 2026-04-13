package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"sigs.k8s.io/controller-runtime/pkg/scheme"
)

var (
	// GroupVersion is the group version used to register these objects.
	GroupVersion = schema.GroupVersion{Group: "authpilot.io", Version: "v1alpha1"}

	// SchemeBuilder is used to add functions to this group's scheme.
	SchemeBuilder = &scheme.Builder{GroupVersion: GroupVersion}

	// AddToScheme adds the types in this group-version to the given scheme.
	AddToScheme = SchemeBuilder.AddToScheme
)

func init() {
	SchemeBuilder.Register(&AuthpilotUser{}, &AuthpilotUserList{})
	SchemeBuilder.Register(&AuthpilotGroup{}, &AuthpilotGroupList{})
}

// ── AuthpilotUser DeepCopy ────────────────────────────────────────────────────

func (in *AuthpilotUser) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *AuthpilotUser) DeepCopy() *AuthpilotUser {
	if in == nil {
		return nil
	}
	out := new(AuthpilotUser)
	in.DeepCopyInto(out)
	return out
}

func (in *AuthpilotUser) DeepCopyInto(out *AuthpilotUser) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	in.Spec.DeepCopyInto(&out.Spec)
	in.Status.DeepCopyInto(&out.Status)
}

func (in *AuthpilotUserSpec) DeepCopyInto(out *AuthpilotUserSpec) {
	*out = *in
	if in.Groups != nil {
		out.Groups = make([]string, len(in.Groups))
		copy(out.Groups, in.Groups)
	}
}

func (in *AuthpilotUserStatus) DeepCopyInto(out *AuthpilotUserStatus) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		copy(out.Conditions, in.Conditions)
	}
}

// ── AuthpilotUserList DeepCopy ────────────────────────────────────────────────

func (in *AuthpilotUserList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *AuthpilotUserList) DeepCopy() *AuthpilotUserList {
	if in == nil {
		return nil
	}
	out := new(AuthpilotUserList)
	in.DeepCopyInto(out)
	return out
}

func (in *AuthpilotUserList) DeepCopyInto(out *AuthpilotUserList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]AuthpilotUser, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}

// ── AuthpilotGroup DeepCopy ───────────────────────────────────────────────────

func (in *AuthpilotGroup) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *AuthpilotGroup) DeepCopy() *AuthpilotGroup {
	if in == nil {
		return nil
	}
	out := new(AuthpilotGroup)
	in.DeepCopyInto(out)
	return out
}

func (in *AuthpilotGroup) DeepCopyInto(out *AuthpilotGroup) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ObjectMeta.DeepCopyInto(&out.ObjectMeta)
	out.Spec = in.Spec
	in.Status.DeepCopyInto(&out.Status)
}

func (in *AuthpilotGroupStatus) DeepCopyInto(out *AuthpilotGroupStatus) {
	*out = *in
	if in.Conditions != nil {
		out.Conditions = make([]metav1.Condition, len(in.Conditions))
		copy(out.Conditions, in.Conditions)
	}
}

// ── AuthpilotGroupList DeepCopy ───────────────────────────────────────────────

func (in *AuthpilotGroupList) DeepCopyObject() runtime.Object { return in.DeepCopy() }

func (in *AuthpilotGroupList) DeepCopy() *AuthpilotGroupList {
	if in == nil {
		return nil
	}
	out := new(AuthpilotGroupList)
	in.DeepCopyInto(out)
	return out
}

func (in *AuthpilotGroupList) DeepCopyInto(out *AuthpilotGroupList) {
	*out = *in
	out.TypeMeta = in.TypeMeta
	in.ListMeta.DeepCopyInto(&out.ListMeta)
	if in.Items != nil {
		out.Items = make([]AuthpilotGroup, len(in.Items))
		for i := range in.Items {
			in.Items[i].DeepCopyInto(&out.Items[i])
		}
	}
}
