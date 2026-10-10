// Admin client for management operations (tenants, applications, roles,
// permissions, memberships, agents). Needs an admin-scoped API key.

using System.Text.Json;

namespace Authz.Sdk;

/// <summary>Options of <see cref="AuthzAdminClient"/>.</summary>
public sealed class AuthzAdminClientOptions
{
    public required string BaseUrl { get; init; }
    public string? ApiKey { get; init; }

    /// <summary>Bring your own client; it is not disposed by the SDK.</summary>
    public HttpClient? HttpClient { get; init; }

    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(10);

    /// <summary>Admin writes are not idempotent, so retries are off by default.</summary>
    public int MaxRetries { get; init; }

    public TimeSpan RetryBackoff { get; init; } = TimeSpan.FromMilliseconds(100);
}

public sealed class AuthzAdminClient : IDisposable
{
    private readonly HttpTransport _http;

    public AuthzAdminClient(AuthzAdminClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _http = new HttpTransport(
            options.BaseUrl, options.ApiKey, options.HttpClient,
            options.Timeout, options.MaxRetries, options.RetryBackoff);
    }

    public AuthzAdminClient(string baseUrl, string? apiKey = null)
        : this(new AuthzAdminClientOptions { BaseUrl = baseUrl, ApiKey = apiKey })
    {
    }

    private static string S(string value) => HttpTransport.Seg(value);

    // ---- Tenants ----------------------------------------------------------------

    public Task<Tenant> CreateTenantAsync(
        string slug, string name, string status = "active", CancellationToken ct = default) =>
        _http.SendAsync<Tenant>(HttpMethod.Post, "v1/tenants", new { slug, name, status }, ct);

    public Task<Tenant> GetTenantAsync(string idOrSlug, CancellationToken ct = default) =>
        _http.SendAsync<Tenant>(HttpMethod.Get, $"v1/tenants/{S(idOrSlug)}", null, ct);

    public Task<JsonElement> MapTenantExternalAsync(
        string tenantId, string provider, string issuer, string externalTenantId,
        CancellationToken ct = default) =>
        _http.SendAsync<JsonElement>(
            HttpMethod.Post, $"v1/tenants/{S(tenantId)}/mappings",
            new { provider, issuer, external_tenant_id = externalTenantId }, ct);

    public Task<JsonElement> SetFeatureFlagAsync(
        string tenantId, string key, object? value, string? applicationId = null,
        CancellationToken ct = default) =>
        _http.SendAsync<JsonElement>(
            HttpMethod.Put, $"v1/tenants/{S(tenantId)}/feature-flags",
            new FeatureFlagBody(key, value, applicationId), ct);

    // ---- Applications -------------------------------------------------------------

    public Task<Application> CreateApplicationAsync(
        string slug, string name, string status = "active", CancellationToken ct = default) =>
        _http.SendAsync<Application>(HttpMethod.Post, "v1/applications", new { slug, name, status }, ct);

    public Task<Application> GetApplicationAsync(string idOrSlug, CancellationToken ct = default) =>
        _http.SendAsync<Application>(HttpMethod.Get, $"v1/applications/{S(idOrSlug)}", null, ct);

    // ---- Roles & permissions --------------------------------------------------------

    public Task<Role> CreateRoleAsync(
        string applicationId, string name, string scope = "application", string? description = null,
        CancellationToken ct = default) =>
        _http.SendAsync<Role>(
            HttpMethod.Post, $"v1/applications/{S(applicationId)}/roles",
            new RoleBody(name, scope, description), ct);

    public Task<IReadOnlyList<Role>> ListRolesAsync(string applicationId, CancellationToken ct = default) =>
        _http.SendAsync<IReadOnlyList<Role>>(
            HttpMethod.Get, $"v1/applications/{S(applicationId)}/roles", null, ct);

    public Task<Permission> CreatePermissionAsync(
        string applicationId, string name, string? description = null, CancellationToken ct = default) =>
        _http.SendAsync<Permission>(
            HttpMethod.Post, $"v1/applications/{S(applicationId)}/permissions",
            new PermissionBody(name, description), ct);

    public Task<IReadOnlyList<Permission>> ListPermissionsAsync(
        string applicationId, CancellationToken ct = default) =>
        _http.SendAsync<IReadOnlyList<Permission>>(
            HttpMethod.Get, $"v1/applications/{S(applicationId)}/permissions", null, ct);

    public async Task SetRolePermissionsAsync(
        string roleId, IEnumerable<string> permissions, CancellationToken ct = default)
    {
        using var _ = await _http.SendRawAsync(
            HttpMethod.Put, $"v1/roles/{S(roleId)}/permissions",
            new { permissions = permissions.ToList() }, ct).ConfigureAwait(false);
    }

    /// <summary>Find-or-create a role by name and set its permissions (idempotent).</summary>
    public async Task<Role> UpsertRoleWithPermissionsAsync(
        string applicationId, string name, IEnumerable<string> permissions,
        string scope = "application", string? description = null, CancellationToken ct = default)
    {
        var roles = await ListRolesAsync(applicationId, ct).ConfigureAwait(false);
        var role = roles.FirstOrDefault(r => r.Name == name)
            ?? await CreateRoleAsync(applicationId, name, scope, description, ct).ConfigureAwait(false);
        await SetRolePermissionsAsync(role.Id, permissions, ct).ConfigureAwait(false);
        return role;
    }

    // ---- Memberships ----------------------------------------------------------------

    public Task<Membership> CreateMembershipAsync(
        string tenantId, string userId, string? applicationId = null,
        IEnumerable<string>? roles = null, string status = "active", CancellationToken ct = default) =>
        _http.SendAsync<Membership>(
            HttpMethod.Post, $"v1/tenants/{S(tenantId)}/memberships",
            new MembershipBody(userId, applicationId, roles?.ToList() ?? [], status), ct);

    public Task<IReadOnlyList<Membership>> ListMembershipsAsync(
        string tenantId, int page = 1, int pageSize = 50, CancellationToken ct = default) =>
        _http.SendAsync<IReadOnlyList<Membership>>(
            HttpMethod.Get, $"v1/tenants/{S(tenantId)}/memberships?page={page}&page_size={pageSize}",
            null, ct);

    // ---- Agents ---------------------------------------------------------------------

    public Task<Agent> CreateAgentAsync(
        string tenantId, string applicationId, string name, string role = "", string status = "active",
        CancellationToken ct = default) =>
        _http.SendAsync<Agent>(
            HttpMethod.Post, $"v1/tenants/{S(tenantId)}/applications/{S(applicationId)}/agents",
            new { name, role, status }, ct);

    public Task<IReadOnlyList<Agent>> ListAgentsAsync(
        string tenantId, string applicationId, CancellationToken ct = default) =>
        _http.SendAsync<IReadOnlyList<Agent>>(
            HttpMethod.Get, $"v1/tenants/{S(tenantId)}/applications/{S(applicationId)}/agents", null, ct);

    public async Task SetAgentRolesAsync(
        string agentId, IEnumerable<string> roles, CancellationToken ct = default)
    {
        using var _ = await _http.SendRawAsync(
            HttpMethod.Put, $"v1/agents/{S(agentId)}/roles", new { roles = roles.ToList() }, ct)
            .ConfigureAwait(false);
    }

    public void Dispose() => _http.Dispose();

    // Bodies with optional fields: nulls are omitted on the wire.
    private sealed record FeatureFlagBody(string Key, object? Value, string? ApplicationId);
    private sealed record RoleBody(string Name, string Scope, string? Description);
    private sealed record PermissionBody(string Name, string? Description);
    private sealed record MembershipBody(string UserId, string? ApplicationId, List<string> Roles, string Status);
}
