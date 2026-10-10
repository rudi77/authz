// Agent-run helpers: preload effective permissions once and hand out guards
// bound to that snapshot, optionally from nothing but a delegation grant.

using System.Text;
using System.Text.Json;

namespace Authz.Sdk;

/// <summary>Guards bound to one permission snapshot of an agent run.</summary>
public sealed record AgentSession(
    ToolGuard Tools,
    McpGuard Mcp,
    IReadOnlySet<string> Permissions,
    string? DelegationToken = null);

/// <summary>Routing claims of a delegation grant (read without verification).</summary>
public sealed record DelegationClaims
{
    public string? DelegationId { get; init; }
    public string TenantId { get; init; } = "";
    public string ApplicationId { get; init; } = "";
    public string UserId { get; init; } = "";
    public string AgentId { get; init; } = "";
    public IReadOnlyList<string> Permissions { get; init; } = [];
    public string? Purpose { get; init; }
    public DateTimeOffset? ExpiresAt { get; init; }

    /// <summary>
    /// Read a grant's routing claims <b>without</b> verifying it. Only for
    /// picking tenant / application / user / agent ids; the service verifies
    /// signature and revocation on every call that carries the token.
    /// </summary>
    public static DelegationClaims Parse(string token)
    {
        var parts = token.Split('.');
        if (parts.Length != 3)
        {
            throw new AuthzClientException("delegation token is not a JWT");
        }
        JsonElement root;
        try
        {
            using var doc = JsonDocument.Parse(Base64UrlDecode(parts[1]));
            root = doc.RootElement.Clone();
        }
        catch (Exception e) when (e is FormatException or JsonException)
        {
            throw new AuthzClientException("delegation token payload is not valid JSON", e);
        }

        var authz = root.TryGetProperty("authz", out var a) && a.ValueKind == JsonValueKind.Object ? a : default;
        var act = root.TryGetProperty("act", out var b) && b.ValueKind == JsonValueKind.Object ? b : default;
        return new DelegationClaims
        {
            DelegationId = Str(root, "jti"),
            TenantId = Str(authz, "tenant_id") ?? "",
            ApplicationId = Str(authz, "application_id") ?? "",
            UserId = Str(root, "sub") ?? "",
            AgentId = Str(act, "sub") ?? "",
            Permissions = authz.ValueKind == JsonValueKind.Object
                && authz.TryGetProperty("permissions", out var p) && p.ValueKind == JsonValueKind.Array
                    ? p.EnumerateArray().Select(x => x.GetString() ?? "").ToList()
                    : [],
            Purpose = Str(authz, "purpose"),
            ExpiresAt = root.TryGetProperty("exp", out var exp) && exp.TryGetInt64(out var secs)
                ? DateTimeOffset.FromUnixTimeSeconds(secs)
                : null,
        };
    }

    private static string? Str(JsonElement obj, string name) =>
        obj.ValueKind == JsonValueKind.Object
        && obj.TryGetProperty(name, out var v) && v.ValueKind == JsonValueKind.String
            ? v.GetString()
            : null;

    private static byte[] Base64UrlDecode(string s)
    {
        var b64 = s.Replace('-', '+').Replace('_', '/');
        b64 += (b64.Length % 4) switch { 2 => "==", 3 => "=", _ => "" };
        return Convert.FromBase64String(b64);
    }

    /// <inheritdoc/>
    public override string ToString() =>
        $"DelegationClaims {{ Id = {DelegationId}, Tenant = {TenantId}, Application = {ApplicationId}, " +
        $"User = {UserId}, Agent = {AgentId} }}";
}

public static class AgentSessionExtensions
{
    /// <summary>
    /// Preload the agent's effective permissions (user ∩ agent ∩ mask, narrowed
    /// by the grant when given) and return guards bound to that snapshot.
    /// </summary>
    public static async Task<AgentSession> StartAgentSessionAsync(
        this AuthzClient client,
        string tenantId,
        string applicationId,
        string userId,
        string agentId,
        string? delegationToken = null,
        CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(client);
        var permissions = await client.GetEffectivePermissionsAsync(new EffectivePermissionsRequest
        {
            TenantId = tenantId,
            ApplicationId = applicationId,
            Subject = Subject.Agent(userId, agentId),
            DelegationToken = delegationToken,
        }, ct).ConfigureAwait(false);
        return new AgentSession(
            new ToolGuard(permissions), new McpGuard(permissions), permissions, delegationToken);
    }

    /// <summary>
    /// Start an agent run from nothing but a delegation grant: tenant,
    /// application, user and agent come from the token.
    /// </summary>
    public static Task<AgentSession> StartDelegatedAgentSessionAsync(
        this AuthzClient client, string delegationToken, CancellationToken ct = default)
    {
        var c = DelegationClaims.Parse(delegationToken);
        return client.StartAgentSessionAsync(
            c.TenantId, c.ApplicationId, c.UserId, c.AgentId, delegationToken, ct);
    }
}
