package provider

import (
	"context"
	"fmt"
	"net/http"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var _ resource.Resource = &GroupResource{}
var _ resource.ResourceWithImportState = &GroupResource{}

func NewGroupResource() resource.Resource { return &GroupResource{} }

type GroupResource struct{ client *Client }

type GroupResourceModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	DisplayName types.String `tfsdk:"display_name"`
}

func (r *GroupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (r *GroupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Manages an Authpilot group via `POST/PUT/DELETE /api/v1/groups`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				MarkdownDescription: "Unique group ID.",
				Required:            true,
				PlanModifiers:       []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				MarkdownDescription: "Machine-readable group name.",
				Required:            true,
			},
			"display_name": schema.StringAttribute{
				MarkdownDescription: "Human-readable display name.",
				Optional:            true,
				Computed:            true,
			},
		},
	}
}

func (r *GroupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (r *GroupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data GroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.apiRequest(http.MethodPost, "/api/v1/groups", map[string]any{
		"id": data.ID.ValueString(), "name": data.Name.ValueString(), "display_name": data.DisplayName.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("create group", err.Error())
		return
	}
	fromGroupAPIResponse(result, &data)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var data GroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.apiRequest(http.MethodGet, "/api/v1/groups/"+data.ID.ValueString(), nil)
	if err != nil {
		resp.Diagnostics.AddError("read group", err.Error())
		return
	}
	fromGroupAPIResponse(result, &data)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var data GroupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	result, err := r.client.apiRequest(http.MethodPut, "/api/v1/groups/"+data.ID.ValueString(), map[string]any{
		"id": data.ID.ValueString(), "name": data.Name.ValueString(), "display_name": data.DisplayName.ValueString(),
	})
	if err != nil {
		resp.Diagnostics.AddError("update group", err.Error())
		return
	}
	fromGroupAPIResponse(result, &data)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (r *GroupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data GroupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if _, err := r.client.apiRequest(http.MethodDelete, "/api/v1/groups/"+data.ID.ValueString(), nil); err != nil {
		resp.Diagnostics.AddError("delete group", err.Error())
	}
}

func (r *GroupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	result, err := r.client.apiRequest(http.MethodGet, "/api/v1/groups/"+req.ID, nil)
	if err != nil {
		resp.Diagnostics.AddError("import group", err.Error())
		return
	}
	var data GroupResourceModel
	fromGroupAPIResponse(result, &data)
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func fromGroupAPIResponse(m map[string]any, data *GroupResourceModel) {
	if v, ok := m["id"].(string); ok {
		data.ID = types.StringValue(v)
	}
	if v, ok := m["name"].(string); ok {
		data.Name = types.StringValue(v)
	}
	if v, ok := m["display_name"].(string); ok {
		data.DisplayName = types.StringValue(v)
	}
}
