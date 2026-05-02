package authz

import (
	"context"
	"fmt"
)

// ToolGuard is a local Policy Enforcement Point for tool calls.
//
// Construct it with the precomputed effective permission set; it answers
// per-call permission checks without contacting the AuthZ service.
type ToolGuard struct {
	permissions map[string]struct{}
}

// NewToolGuard creates a guard from a permission set.
func NewToolGuard(permissions map[string]struct{}) *ToolGuard {
	if permissions == nil {
		permissions = map[string]struct{}{}
	}
	return &ToolGuard{permissions: permissions}
}

// IsAllowed returns whether the (resource, action) is in the permission set.
func (g *ToolGuard) IsAllowed(resource, action string) bool {
	_, ok := g.permissions[resource+"."+action]
	return ok
}

// Require returns an error wrapping ErrPermissionDenied when missing.
func (g *ToolGuard) Require(resource, action string) error {
	if !g.IsAllowed(resource, action) {
		return fmt.Errorf("%w: %s.%s", ErrPermissionDenied, resource, action)
	}
	return nil
}

// MCPGuard mirrors ToolGuard but namespaces checks under "mcp.".
type MCPGuard struct {
	permissions map[string]struct{}
}

// NewMCPGuard creates a guard tied to the mcp.* namespace.
func NewMCPGuard(permissions map[string]struct{}) *MCPGuard {
	if permissions == nil {
		permissions = map[string]struct{}{}
	}
	return &MCPGuard{permissions: permissions}
}

// IsAllowed returns whether mcp.<server>.<action> is allowed.
func (g *MCPGuard) IsAllowed(server, action string) bool {
	_, ok := g.permissions["mcp."+server+"."+action]
	return ok
}

// Require returns ErrPermissionDenied when the MCP tool is not allowed.
func (g *MCPGuard) Require(server, action string) error {
	if !g.IsAllowed(server, action) {
		return fmt.Errorf("%w: mcp.%s.%s", ErrPermissionDenied, server, action)
	}
	return nil
}

// StartAgentSession preloads the effective permission set for a (user, agent)
// pair and returns guards bound to that snapshot. Equivalent to the Python
// ``start_agent_session`` helper.
func StartAgentSession(
	ctx context.Context,
	client *Client,
	tenantID, applicationID, userID, agentID string,
) (*ToolGuard, *MCPGuard, error) {
	perms, err := client.GetEffectivePermissions(ctx, EffectivePermissionsRequest{
		TenantID:      tenantID,
		ApplicationID: applicationID,
		Subject: Subject{
			Type:    "agent",
			UserID:  userID,
			AgentID: agentID,
		},
	})
	if err != nil {
		return nil, nil, err
	}
	return NewToolGuard(perms), NewMCPGuard(perms), nil
}
