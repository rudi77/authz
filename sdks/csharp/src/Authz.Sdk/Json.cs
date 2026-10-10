using System.Text.Json;
using System.Text.Json.Serialization;

namespace Authz.Sdk;

internal static class Json
{
    /// <summary>
    /// snake_case on the wire, null fields omitted (the service treats a
    /// missing field like null). Dictionary keys (context, claims) are left
    /// untouched.
    /// </summary>
    public static readonly JsonSerializerOptions Options = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.SnakeCaseLower,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
        PropertyNameCaseInsensitive = true,
    };
}
