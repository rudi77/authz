package authz

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Tenant represents a tenant resource.
type Tenant struct {
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Application represents an application resource.
type Application struct {
	ID     string `json:"id"`
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Status string `json:"status"`
}

// Role represents a role resource.
type Role struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Scope         string  `json:"scope"`
	ApplicationID *string `json:"application_id"`
	TenantID      *string `json:"tenant_id"`
	Description   *string `json:"description"`
	IsSystem      bool    `json:"is_system"`
}

// Permission represents a permission resource.
type Permission struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Resource      string  `json:"resource"`
	Action        string  `json:"action"`
	ApplicationID *string `json:"application_id"`
	Description   *string `json:"description"`
}

// Membership represents a tenant membership.
type Membership struct {
	ID            string   `json:"id"`
	TenantID      string   `json:"tenant_id"`
	ApplicationID *string  `json:"application_id"`
	UserID        string   `json:"user_id"`
	Roles         []string `json:"roles"`
	Status        string   `json:"status"`
}

// Agent represents an agent resource.
type Agent struct {
	ID            string `json:"id"`
	TenantID      string `json:"tenant_id"`
	ApplicationID string `json:"application_id"`
	Name          string `json:"name"`
	Role          string `json:"role"`
	Status        string `json:"status"`
}

// AdminClient handles management operations against the AuthZ service.
type AdminClient struct {
	baseURL    string
	apiKey     string
	httpClient *http.Client
}

// NewAdminClient builds an AdminClient.
func NewAdminClient(baseURL, apiKey string, opts ...AdminOption) *AdminClient {
	c := &AdminClient{
		baseURL:    baseURL,
		apiKey:     apiKey,
		httpClient: &http.Client{Timeout: 10 * time.Second},
	}
	for _, o := range opts {
		o(c)
	}
	return c
}

// AdminOption configures an AdminClient.
type AdminOption func(*AdminClient)

// AdminWithHTTPClient overrides the HTTP client.
func AdminWithHTTPClient(h *http.Client) AdminOption {
	return func(c *AdminClient) { c.httpClient = h }
}

func (c *AdminClient) request(ctx context.Context, method, path string, body, out any) error {
	url := c.baseURL
	if url[len(url)-1] != '/' {
		url += "/"
	}
	url += path

	var bodyReader io.Reader
	if body != nil {
		payload, err := json.Marshal(body)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(payload)
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if c.apiKey != "" {
		req.Header.Set("X-API-Key", c.apiKey)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("authz: transport error: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)

	if resp.StatusCode >= 400 {
		var detail any
		if e := json.Unmarshal(respBody, &detail); e != nil {
			detail = string(respBody)
		}
		return &ServiceError{StatusCode: resp.StatusCode, Body: detail}
	}
	if out != nil && len(respBody) > 0 {
		return json.Unmarshal(respBody, out)
	}
	return nil
}

// CreateTenant creates a tenant.
func (c *AdminClient) CreateTenant(ctx context.Context, slug, name string) (*Tenant, error) {
	body := map[string]string{"slug": slug, "name": name, "status": "active"}
	var out Tenant
	if err := c.request(ctx, "POST", "v1/tenants", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetTenant fetches a tenant by id or slug.
func (c *AdminClient) GetTenant(ctx context.Context, idOrSlug string) (*Tenant, error) {
	var out Tenant
	if err := c.request(ctx, "GET", "v1/tenants/"+idOrSlug, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateApplication creates an application.
func (c *AdminClient) CreateApplication(ctx context.Context, slug, name string) (*Application, error) {
	body := map[string]string{"slug": slug, "name": name, "status": "active"}
	var out Application
	if err := c.request(ctx, "POST", "v1/applications", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetApplication fetches an application by id or slug.
func (c *AdminClient) GetApplication(ctx context.Context, idOrSlug string) (*Application, error) {
	var out Application
	if err := c.request(ctx, "GET", "v1/applications/"+idOrSlug, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreatePermission registers a permission.
func (c *AdminClient) CreatePermission(ctx context.Context, applicationID, name string) (*Permission, error) {
	body := map[string]string{"name": name}
	var out Permission
	if err := c.request(ctx, "POST", "v1/applications/"+applicationID+"/permissions", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateRole registers a role.
func (c *AdminClient) CreateRole(ctx context.Context, applicationID, name, scope string) (*Role, error) {
	body := map[string]string{"name": name, "scope": scope}
	var out Role
	if err := c.request(ctx, "POST", "v1/applications/"+applicationID+"/roles", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetRolePermissions replaces a role's permission set.
func (c *AdminClient) SetRolePermissions(ctx context.Context, roleID string, permissions []string) error {
	return c.request(
		ctx, "PUT", "v1/roles/"+roleID+"/permissions",
		map[string][]string{"permissions": permissions},
		nil,
	)
}

// CreateMembership grants a user a membership in a tenant.
func (c *AdminClient) CreateMembership(
	ctx context.Context,
	tenantID, userID, applicationID string,
	roles []string,
) (*Membership, error) {
	body := map[string]any{
		"user_id":        userID,
		"application_id": applicationID,
		"roles":          roles,
		"status":         "active",
	}
	var out Membership
	if err := c.request(ctx, "POST", "v1/tenants/"+tenantID+"/memberships", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// CreateAgent creates an agent under a tenant + application.
func (c *AdminClient) CreateAgent(ctx context.Context, tenantID, applicationID, name, role string) (*Agent, error) {
	body := map[string]string{"name": name, "role": role, "status": "active"}
	var out Agent
	if err := c.request(
		ctx, "POST",
		"v1/tenants/"+tenantID+"/applications/"+applicationID+"/agents",
		body, &out,
	); err != nil {
		return nil, err
	}
	return &out, nil
}

// SetAgentRoles replaces an agent's role set.
func (c *AdminClient) SetAgentRoles(ctx context.Context, agentID string, roles []string) error {
	return c.request(
		ctx, "PUT", "v1/agents/"+agentID+"/roles",
		map[string][]string{"roles": roles},
		nil,
	)
}
