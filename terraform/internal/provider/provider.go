// Package provider implements the Furnace Terraform provider.
//
// Resources:
//   - furnace_user   → POST/PUT/DELETE /api/v1/users
//   - furnace_group  → POST/PUT/DELETE /api/v1/groups
//
// Provider configuration:
//
//	provider "furnace" {
//	  base_url = "http://localhost:8025"
//	  api_key  = var.furnace_api_key
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

// Ensure FurnaceProvider satisfies the provider.Provider interface.
var _ provider.Provider = &FurnaceProvider{}

// FurnaceProvider defines the provider implementation.
type FurnaceProvider struct {
	version string
}

// FurnaceProviderModel describes the provider data model.
type FurnaceProviderModel struct {
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
		return &FurnaceProvider{version: version}
	}
}

func (p *FurnaceProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "furnace"
	resp.Version = p.version
}

func (p *FurnaceProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Provider for managing Furnace users, groups, and tenants via the management API.",
		Attributes: map[string]schema.Attribute{
			"base_url": schema.StringAttribute{
				MarkdownDescription: "Base URL of the Furnace management API (e.g. `http://localhost:8025`). " +
					"Can also be set via `FURNACE_BASE_URL` environment variable.",
				Optional: true,
			},
			"api_key": schema.StringAttribute{
				MarkdownDescription: "API key for the Furnace management API. " +
					"Can also be set via `FURNACE_API_KEY` environment variable.",
				Optional:  true,
				Sensitive: true,
			},
		},
	}
}

func (p *FurnaceProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data FurnaceProviderModel
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

func (p *FurnaceProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewUserResource,
		NewGroupResource,
	}
}

func (p *FurnaceProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}
