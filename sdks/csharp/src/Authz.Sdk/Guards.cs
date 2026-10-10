// Local Policy Enforcement Points against a preloaded permission snapshot.

namespace Authz.Sdk;

/// <summary>Checks <c>&lt;resource&gt;.&lt;action&gt;</c> permissions locally.</summary>
public sealed class ToolGuard
{
    private readonly HashSet<string> _permissions;

    public ToolGuard(IEnumerable<string> permissions)
    {
        _permissions = new HashSet<string>(permissions, StringComparer.Ordinal);
    }

    public bool IsAllowed(string resource, string action) =>
        _permissions.Contains($"{resource}.{action}");

    public void Require(string resource, string action)
    {
        if (!IsAllowed(resource, action))
        {
            throw new PermissionDeniedException($"{resource}.{action}");
        }
    }
}

/// <summary>Checks MCP tool permissions, namespaced as <c>mcp.&lt;server&gt;.&lt;tool&gt;</c>.</summary>
public sealed class McpGuard
{
    private readonly HashSet<string> _permissions;

    public McpGuard(IEnumerable<string> permissions)
    {
        _permissions = new HashSet<string>(permissions, StringComparer.Ordinal);
    }

    public bool IsAllowed(string server, string action) =>
        _permissions.Contains($"mcp.{server}.{action}");

    public void Require(string server, string action)
    {
        if (!IsAllowed(server, action))
        {
            throw new PermissionDeniedException($"mcp.{server}.{action}");
        }
    }

    /// <summary>Tool names of <paramref name="server"/> the snapshot allows, e.g. to filter a tool list.</summary>
    public IReadOnlyList<string> AllowedTools(string server)
    {
        var prefix = $"mcp.{server}.";
        return _permissions
            .Where(p => p.StartsWith(prefix, StringComparison.Ordinal))
            .Select(p => p[prefix.Length..])
            .Order(StringComparer.Ordinal)
            .ToList();
    }
}
