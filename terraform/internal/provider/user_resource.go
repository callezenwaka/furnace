package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &UserResource{}
var _ resource.ResourceWithImportState = &UserResource{}

func NewUserResource() resource.Resource { return &UserResource{} }

type UserResource struct{ client *Client }

type UserResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Email       types.String `tfsdk:"email"`
	DisplayName types.String `tfsdk:"display_name"`
	MFAMethod   types.String `tfsdk:"mfa_method"`
	Active      types.Bool   `tfsdk:"active"`
	Groups      types.List   `tfsdk:"groups"`
}

func (r *UserResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (r *UserResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an Furnace user via `POST/PUT/DELETE /api/v1/users`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Unique user ID.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"email": schema.StringAttribute{
				MarkdownDescription: "User email address.",
				Required:            true,
			},
			"display_name": schema.StringAttribute{
				MarkdownDescription: "Human-readable display name.",
				Optional:            true,
				Computed:            true,
			},
			"mfa_method": schema.StringAttribute{
				MarkdownDescription: "MFA method: none, totp, sms, push, magic_link, webauthn.",
				Optional:            true,
				Computed:            true,
			},
			"active": schema.BoolAttribute{
				MarkdownDescription: "Whether the user is active. Defaults to true.",
				Optional:            true,
				Computed:            true,
				Default:             booldefault.StaticBool(true),
			},
			"groups": schema.ListAttribute{
				MarkdownDescription: "Group IDs the user belongs to.",
				Optional:            true,
				Computed:            true,
				ElementType:         types.StringType,
			},
		},
	}
}

func (r *UserResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	client, ok := req.ProviderData.(*Client)
	if !ok {
		resp.Diagnostics.AddError("unexpected provider data type", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	r.client = client
}

func (r *UserResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data UserResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, err := r.toAPIBody(ctx, data)
	if err != nil {
		resp.Diagnostics.AddError("serialize user", err.Error())
		return
	}
	result, err := r.client.apiRequest(http.MethodPost, "/api/v1/users", body)
	if err != nil {
		resp.Diagnostics.AddError("create user", err.Error())
		return
	}
	r.fromAPIResponse(ctx, result, &data)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UserResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data UserResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.apiRequest(http.MethodGet, "/api/v1/users/"+data.ID.ValueString(), nil)
	if err != nil {
		resp.Diagnostics.AddError("read user", err.Error())
		return
	}
	r.fromAPIResponse(ctx, result, &data)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UserResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data UserResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, err := r.toAPIBody(ctx, data)
	if err != nil {
		resp.Diagnostics.AddError("serialize user", err.Error())
		return
	}
	result, err := r.client.apiRequest(http.MethodPut, "/api/v1/users/"+data.ID.ValueString(), body)
	if err != nil {
		resp.Diagnostics.AddError("update user", err.Error())
		return
	}
	r.fromAPIResponse(ctx, result, &data)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UserResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data UserResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if _, err := r.client.apiRequest(http.MethodDelete, "/api/v1/users/"+data.ID.ValueString(), nil); err != nil {
		resp.Diagnostics.AddError("delete user", err.Error())
	}
}

func (r *UserResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	result, err := r.client.apiRequest(http.MethodGet, "/api/v1/users/"+req.ID, nil)
	if err != nil {
		resp.Diagnostics.AddError("import user", err.Error())
		return
	}
	var data UserResourceModel
	r.fromAPIResponse(ctx, result, &data)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *UserResource) toAPIBody(ctx context.Context, m UserResourceModel) (map[string]any, error) {
	body := map[string]any{
		"id":           m.ID.ValueString(),
		"email":        m.Email.ValueString(),
		"display_name": m.DisplayName.ValueString(),
		"mfa_method":   m.MFAMethod.ValueString(),
		"active":       m.Active.ValueBool(),
	}
	var groups []string
	if !m.Groups.IsNull() && !m.Groups.IsUnknown() {
		diags := m.Groups.ElementsAs(ctx, &groups, false)
		if diags.HasError() {
			return nil, fmt.Errorf("groups: %v", diags)
		}
	}
	body["groups"] = groups
	return body, nil
}

func (r *UserResource) fromAPIResponse(ctx context.Context, m map[string]any, data *UserResourceModel) {
	if v, ok := m["id"].(string); ok {
		data.ID = types.StringValue(v)
	}
	if v, ok := m["email"].(string); ok {
		data.Email = types.StringValue(v)
	}
	if v, ok := m["display_name"].(string); ok {
		data.DisplayName = types.StringValue(v)
	}
	if v, ok := m["mfa_method"].(string); ok {
		data.MFAMethod = types.StringValue(v)
	}
	if v, ok := m["active"].(bool); ok {
		data.Active = types.BoolValue(v)
	}
	if raw, ok := m["groups"].([]any); ok {
		elems := make([]types.String, 0, len(raw))
		for _, g := range raw {
			if s, ok := g.(string); ok {
				elems = append(elems, types.StringValue(s))
			}
		}
		listVal, _ := types.ListValueFrom(ctx, types.StringType, elems)
		data.Groups = listVal
	}
}
