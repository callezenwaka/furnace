// Package provider implements the Authpilot Terraform provider.
//
// Resources:
//   - authpilot_user   → POST/PUT/DELETE /api/v1/users
//   - authpilot_group  → POST/PUT/DELETE /api/v1/groups
//
// Provider configuration:
//
//	provider "authpilot" {
//	  base_url = "http://localhost:8025"
//	  api_key  = var.authpilot_api_key
//	}
package provider

import (
	"context"
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure AuthpilotProvider satisfies the provider.Provider interface.
var _ provider.Provider = &AuthpilotProvider{}

// AuthpilotProvider defines the provider implementation.
type AuthpilotProvider struct {
	version string
}

// AuthpilotProviderModel describes the provider data model.
type AuthpilotProviderModel struct {
	BaseURL types.String `tfsdk:"base_url"`
	APIKey  types.String `tfsdk:"api_key"`
}

// Client is the shared API client passed to resources.
type Client struct {
	BaseURL    string
	APIKey     string
	HTTPClient *http.Client
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &AuthpilotProvider{version: version}
	}
}

func (p *AuthpilotProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "authpilot"
	resp.Version = p.version
}

func (p *AuthpilotProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Provider for managing Authpilot users, groups, and tenants via the management API.",
		Attributes: map[string]schema.Attribute{
			"base_url": schema.StringAttribute{
				MarkdownDescription: "Base URL of the Authpilot management API (e.g. `http://localhost:8025`). " +
					"Can also be set via `AUTHPILOT_BASE_URL` environment variable.",
				Optional: true,
			},
			"api_key": schema.StringAttribute{
				MarkdownDescription: "API key for the Authpilot management API. " +
					"Can also be set via `AUTHPILOT_API_KEY` environment variable.",
				Optional:  true,
				Sensitive: true,
			},
		},
	}
}

func (p *AuthpilotProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data AuthpilotProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	baseURL := data.BaseURL.ValueString()
	if baseURL == "" {
		baseURL = "http://localhost:8025"
	}
	apiKey := data.APIKey.ValueString()

	client := &Client{
		BaseURL: baseURL,
		APIKey:  apiKey,
		HTTPClient: &http.Client{
			Timeout: 15 * time.Second,
		},
	}

	resp.DataSourceData = client
	resp.ResourceData = client
}

func (p *AuthpilotProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewUserResource,
		NewGroupResource,
	}
}

func (p *AuthpilotProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}
