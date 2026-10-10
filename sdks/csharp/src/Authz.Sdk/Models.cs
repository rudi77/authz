// Shared types between the runtime and admin clients.
//
// Field shapes mirror the Pydantic schemas of the service. Properties are
// PascalCase; the JSON layer (Json.cs) maps them to the snake_case wire format,
// so this is the only file that needs to know the shapes.

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Authz.Sdk;

/// <summary>Subject types understood by the service.</summary>
public static class SubjectTypes
{
    public const string User = "user";
    public const string Agent = "agent";
    public const string ServiceAccount = "service_account";
    public const string ApiKey = "api_key";
}

/// <summary>A user by IdP identity, an alternative to the authz user id.</summary>
public sealed record UserRef(string Provider, string Issuer, string Subject);

/// <summary>
/// Who acts. <see cref="UserRef"/> / <see cref="AgentName"/> are alternatives to
/// the ids; the service resolves them (give one form per field).
/// </summary>
public sealed record Subject
{
    public required string Type { get; init; }
    public string? UserId { get; init; }
    public string? AgentId { get; init; }
    public string? ServiceAccountId { get; init; }
    public UserRef? UserRef { get; init; }
    public string? AgentName { get; init; }

    /// <summary>A user acting on their own behalf.</summary>
    public static Subject User(string userId) => new() { Type = SubjectTypes.User, UserId = userId };

    /// <summary>An agent acting for a user: effective set is user ∩ agent.</summary>
    public static Subject Agent(string userId, string agentId) =>
        new() { Type = SubjectTypes.Agent, UserId = userId, AgentId = agentId };
}

/// <summary>A (resource, action) pair to be evaluated in a bulk call.</summary>
public sealed record BulkCheck(string Resource, string Action);

/// <summary>One row of a bulk-authorize response.</summary>
public sealed record BulkCheckResult
{
    public string Resource { get; init; } = "";
    public string Action { get; init; } = "";
    public bool Allowed { get; init; }
    public string Reason { get; init; } = "";
}

/// <summary>Response of <c>/v1/resolve-context</c>.</summary>
public sealed record ResolvedContext
{
    public string TenantId { get; init; } = "";
    public string ApplicationId { get; init; } = "";
    public string UserId { get; init; } = "";
    public IReadOnlyList<string> Roles { get; init; } = [];
    public IReadOnlyList<string> Permissions { get; init; } = [];
}

/// <summary>Structured result of a <c>/v1/authorize</c> decision.</summary>
public sealed record AuthorizeResult
{
    public bool Allowed { get; init; }
    public string Decision { get; init; } = "";
    public string Reason { get; init; } = "";
    public string RequiredPermission { get; init; } = "";
    public IReadOnlyList<string> MatchedPermissions { get; init; } = [];
}

/// <summary>Input of <see cref="AuthzClient.AuthorizeAsync"/>.</summary>
public sealed record AuthorizeRequest
{
    public required string TenantId { get; init; }
    public required string ApplicationId { get; init; }
    public required Subject Subject { get; init; }
    public required string Resource { get; init; }
    public required string Action { get; init; }
    public IReadOnlyDictionary<string, object?>? Context { get; init; }

    /// <summary>Optional grant, sent as <c>X-Delegation-Token</c>.</summary>
    [JsonIgnore]
    public string? DelegationToken { get; init; }
}

/// <summary>Input of <see cref="AuthzClient.BulkAuthorizeAsync"/>.</summary>
public sealed record BulkAuthorizeRequest
{
    public required string TenantId { get; init; }
    public required string ApplicationId { get; init; }
    public required Subject Subject { get; init; }
    public required IReadOnlyList<BulkCheck> Checks { get; init; }
    public IReadOnlyDictionary<string, object?>? Context { get; init; }

    /// <summary>Optional grant, sent as <c>X-Delegation-Token</c>.</summary>
    [JsonIgnore]
    public string? DelegationToken { get; init; }
}

/// <summary>Input of <see cref="AuthzClient.GetEffectivePermissionsAsync"/>.</summary>
public sealed record EffectivePermissionsRequest
{
    public required string TenantId { get; init; }
    public required string ApplicationId { get; init; }
    public required Subject Subject { get; init; }

    /// <summary>Skip the local cache and ask the service.</summary>
    [JsonIgnore]
    public bool BypassCache { get; init; }

    /// <summary>Optional grant, sent as <c>X-Delegation-Token</c>.</summary>
    [JsonIgnore]
    public string? DelegationToken { get; init; }
}

/// <summary>Input of <see cref="AuthzClient.ResolveContextAsync"/>.</summary>
public sealed record ResolveContextRequest
{
    public required string ApplicationId { get; init; }
    public required string Provider { get; init; }
    public required string Issuer { get; init; }
    public required string Subject { get; init; }
    public string? Email { get; init; }
    public string? ExternalTenantId { get; init; }
    public string? ExplicitTenantId { get; init; }
    public IReadOnlyDictionary<string, object?> Claims { get; init; } = new Dictionary<string, object?>();
}

/// <summary>
/// Input of <see cref="AuthzClient.CreateDelegationAsync"/>. Give the user as
/// <see cref="UserId"/> or <see cref="UserRef"/> and the agent as
/// <see cref="AgentId"/> or <see cref="AgentName"/>. <see cref="Permissions"/>
/// = null delegates everything the agent may currently do for this user.
/// </summary>
public sealed record CreateDelegationRequest
{
    public required string TenantId { get; init; }
    public required string ApplicationId { get; init; }
    public string? UserId { get; init; }
    public UserRef? UserRef { get; init; }
    public string? AgentId { get; init; }
    public string? AgentName { get; init; }
    public IReadOnlyList<string>? Permissions { get; init; }
    public int? TtlSeconds { get; init; }
    public string? Purpose { get; init; }
}

/// <summary>Input of the delegation kill switch. <see cref="AgentName"/> needs <see cref="ApplicationId"/>.</summary>
public sealed record RevokeDelegationsRequest
{
    public required string TenantId { get; init; }
    public string? ApplicationId { get; init; }
    public string? UserId { get; init; }
    public UserRef? UserRef { get; init; }
    public string? AgentId { get; init; }
    public string? AgentName { get; init; }
}

/// <summary>A delegation grant. <see cref="Token"/> is only set on the issuance response.</summary>
public sealed record Delegation
{
    public string Id { get; init; } = "";
    public string TenantId { get; init; } = "";
    public string ApplicationId { get; init; } = "";
    public string UserId { get; init; } = "";
    public string AgentId { get; init; } = "";
    public IReadOnlyList<string> Permissions { get; init; } = [];
    public string? Purpose { get; init; }
    public string? IssuedBy { get; init; }
    public string Status { get; init; } = "active";
    public bool Active { get; init; } = true;
    public DateTimeOffset ExpiresAt { get; init; }
    public DateTimeOffset? RevokedAt { get; init; }
    public DateTimeOffset? CreatedAt { get; init; }
    public string? Token { get; init; }
}

/// <summary>Result of token introspection. Inactive results carry a <see cref="Reason"/>.</summary>
public sealed record DelegationIntrospection
{
    public bool Active { get; init; }
    public string? Reason { get; init; }

    /// <summary>Every other field of the response (claims of an active grant).</summary>
    [JsonExtensionData]
    public Dictionary<string, JsonElement> Extra { get; init; } = new();
}

public sealed record Tenant
{
    public string Id { get; init; } = "";
    public string Slug { get; init; } = "";
    public string Name { get; init; } = "";
    public string Status { get; init; } = "";
}

public sealed record Application
{
    public string Id { get; init; } = "";
    public string Slug { get; init; } = "";
    public string Name { get; init; } = "";
    public string Status { get; init; } = "";
}

public sealed record Role
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string Scope { get; init; } = "";
    public string? ApplicationId { get; init; }
    public string? TenantId { get; init; }
    public string? Description { get; init; }
    public bool IsSystem { get; init; }
}

public sealed record Permission
{
    public string Id { get; init; } = "";
    public string Name { get; init; } = "";
    public string Resource { get; init; } = "";
    public string Action { get; init; } = "";
    public string? ApplicationId { get; init; }
    public string? Description { get; init; }
}

public sealed record Membership
{
    public string Id { get; init; } = "";
    public string TenantId { get; init; } = "";
    public string? ApplicationId { get; init; }
    public string UserId { get; init; } = "";
    public IReadOnlyList<string> Roles { get; init; } = [];
    public string Status { get; init; } = "";
}

public sealed record Agent
{
    public string Id { get; init; } = "";
    public string TenantId { get; init; } = "";
    public string ApplicationId { get; init; } = "";
    public string Name { get; init; } = "";
    public string Role { get; init; } = "";
    public string Status { get; init; } = "";
}
