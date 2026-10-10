using System.Text.Json;

namespace Authz.Sdk;

/// <summary>Base error for SDK-level problems (transport, validation).</summary>
public class AuthzClientException : Exception
{
    public AuthzClientException(string message, Exception? inner = null) : base(message, inner) { }
}

/// <summary>The service returned a non-success status code.</summary>
public class AuthzServiceException : AuthzClientException
{
    public AuthzServiceException(int statusCode, string body)
        : base($"AuthZ service returned {statusCode}: {body}")
    {
        StatusCode = statusCode;
        Body = body;
        try
        {
            using var doc = JsonDocument.Parse(body);
            Detail = doc.RootElement.Clone();
        }
        catch (JsonException)
        {
            Detail = null;
        }
    }

    public int StatusCode { get; }

    /// <summary>Raw response body.</summary>
    public string Body { get; }

    /// <summary>Parsed body, or null when it is not JSON.</summary>
    public JsonElement? Detail { get; }

    /// <summary>
    /// Machine-readable code from <c>{"detail": {"reason"|"error": …}}</c>,
    /// e.g. <c>agent_not_found</c> or <c>no_active_user_membership</c>.
    /// </summary>
    public string? ErrorCode
    {
        get
        {
            if (Detail is not { ValueKind: JsonValueKind.Object } root
                || !root.TryGetProperty("detail", out var detail)
                || detail.ValueKind != JsonValueKind.Object)
            {
                return null;
            }
            foreach (var key in new[] { "reason", "error" })
            {
                if (detail.TryGetProperty(key, out var v) && v.ValueKind == JsonValueKind.String)
                {
                    return v.GetString();
                }
            }
            return null;
        }
    }
}

/// <summary>Thrown by <c>Require</c> methods when the subject lacks the permission.</summary>
public class PermissionDeniedException : AuthzClientException
{
    public PermissionDeniedException(string permission) : base($"Permission denied: {permission}")
    {
        Permission = permission;
    }

    public string Permission { get; }
}
