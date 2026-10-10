// Runtime AuthzClient: thin wrapper over the service's runtime endpoints.
//
// Includes a bounded LRU cache of effective permissions keyed by
// (tenant, application, subject, grant), so an agent runtime can preload its
// permission set at the start of a session and avoid a round-trip per tool call.

using System.Security.Cryptography;
using System.Text;

namespace Authz.Sdk;

/// <summary>Options of <see cref="AuthzClient"/>.</summary>
public sealed class AuthzClientOptions
{
    public required string BaseUrl { get; init; }
    public string? ApiKey { get; init; }

    /// <summary>
    /// Bring your own client (mTLS, handlers, <c>IHttpClientFactory</c>). It is
    /// not disposed by the SDK.
    /// </summary>
    public HttpClient? HttpClient { get; init; }

    /// <summary>Timeout per attempt.</summary>
    public TimeSpan Timeout { get; init; } = TimeSpan.FromSeconds(5);

    /// <summary>Effective-permissions cache TTL. Zero disables caching.</summary>
    public TimeSpan CacheTtl { get; init; } = TimeSpan.Zero;

    public int CacheMaxEntries { get; init; } = 1024;
    public int MaxRetries { get; init; } = 2;
    public TimeSpan RetryBackoff { get; init; } = TimeSpan.FromMilliseconds(100);

    /// <summary>Clock for cache expiry; tests inject a fake one.</summary>
    public TimeProvider? TimeProvider { get; init; }
}

/// <summary>
/// Runtime client of the AuthZ service (the PDP). Safe for concurrent use; the
/// cache is guarded by an internal lock.
/// </summary>
public sealed class AuthzClient : IDisposable
{
    private readonly HttpTransport _http;
    private readonly TimeSpan _cacheTtl;
    private readonly int _cacheMax;
    private readonly TimeProvider _clock;

    private readonly object _cacheLock = new();
    private readonly Dictionary<string, LinkedListNode<CacheEntry>> _cache = new();
    private readonly LinkedList<CacheEntry> _lru = new(); // Most recently used last.

    private sealed record CacheEntry(
        string Key, string TenantId, string ApplicationId, HashSet<string> Permissions, DateTimeOffset ExpiresAt);

    public AuthzClient(AuthzClientOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        _http = new HttpTransport(
            options.BaseUrl, options.ApiKey, options.HttpClient,
            options.Timeout, options.MaxRetries, options.RetryBackoff);
        _cacheTtl = options.CacheTtl;
        _cacheMax = Math.Max(1, options.CacheMaxEntries);
        _clock = options.TimeProvider ?? TimeProvider.System;
    }

    public AuthzClient(string baseUrl, string? apiKey = null)
        : this(new AuthzClientOptions { BaseUrl = baseUrl, ApiKey = apiKey })
    {
    }

    // ---- Decisions ------------------------------------------------------------

    /// <summary>Map an IdP identity to a tenant-bound user context.</summary>
    public Task<ResolvedContext> ResolveContextAsync(
        ResolveContextRequest request, CancellationToken ct = default) =>
        _http.SendAsync<ResolvedContext>(HttpMethod.Post, "v1/resolve-context", request, ct);

    /// <summary>Run a single decision.</summary>
    public Task<AuthorizeResult> AuthorizeAsync(
        AuthorizeRequest request, CancellationToken ct = default) =>
        _http.SendAsync<AuthorizeResult>(
            HttpMethod.Post, "v1/authorize", WithContext(request), ct, request.DelegationToken);

    /// <summary>Throw <see cref="PermissionDeniedException"/> unless the decision is allow.</summary>
    public async Task RequireAsync(AuthorizeRequest request, CancellationToken ct = default)
    {
        var result = await AuthorizeAsync(request, ct).ConfigureAwait(false);
        if (!result.Allowed)
        {
            var permission = string.IsNullOrEmpty(result.RequiredPermission)
                ? $"{request.Resource}.{request.Action}"
                : result.RequiredPermission;
            throw new PermissionDeniedException(permission);
        }
    }

    /// <summary>Evaluate many checks in one round-trip (subject resolved once).</summary>
    public async Task<IReadOnlyList<BulkCheckResult>> BulkAuthorizeAsync(
        BulkAuthorizeRequest request, CancellationToken ct = default)
    {
        var body = request.Context is null ? request with { Context = Empty } : request;
        var response = await _http.SendAsync<BulkResponse>(
            HttpMethod.Post, "v1/bulk-authorize", body, ct, request.DelegationToken).ConfigureAwait(false);
        return response.Results;
    }

    /// <summary>
    /// The subject's effective permission set (for agents: user ∩ agent ∩ mask,
    /// narrowed by the grant if one is given). Cached for
    /// <see cref="AuthzClientOptions.CacheTtl"/>; the returned set is a copy.
    /// </summary>
    public async Task<IReadOnlySet<string>> GetEffectivePermissionsAsync(
        EffectivePermissionsRequest request, CancellationToken ct = default)
    {
        var key = CacheKey(request);
        if (_cacheTtl > TimeSpan.Zero && !request.BypassCache && TryGetCached(key, out var cached))
        {
            return cached;
        }

        var response = await _http.SendAsync<PermissionsResponse>(
            HttpMethod.Post, "v1/effective-permissions", request, ct, request.DelegationToken)
            .ConfigureAwait(false);
        var permissions = new HashSet<string>(response.Permissions, StringComparer.Ordinal);
        if (_cacheTtl > TimeSpan.Zero)
        {
            Put(key, request.TenantId, request.ApplicationId, permissions);
        }
        return new HashSet<string>(permissions, StringComparer.Ordinal);
    }

    /// <summary>
    /// Drop cached entries matching the given partition keys (null matches all).
    /// Use when admins changed memberships and a long-running runtime needs a
    /// fresh set.
    /// </summary>
    public void InvalidateCache(string? tenantId = null, string? applicationId = null)
    {
        lock (_cacheLock)
        {
            var node = _lru.First;
            while (node is not null)
            {
                var next = node.Next;
                var e = node.Value;
                if ((tenantId is null || e.TenantId == tenantId)
                    && (applicationId is null || e.ApplicationId == applicationId))
                {
                    _lru.Remove(node);
                    _cache.Remove(e.Key);
                }
                node = next;
            }
        }
    }

    // ---- Delegation grants ------------------------------------------------------

    /// <summary>
    /// Issue a grant; hand <see cref="Delegation.Token"/> to the agent runtime.
    /// A subset outside user ∩ agent is rejected (403); an inactive user or agent
    /// gets 409. Not retried, so a 5xx never issues two grants.
    /// </summary>
    public Task<Delegation> CreateDelegationAsync(
        CreateDelegationRequest request, CancellationToken ct = default)
    {
        var body = request.Permissions is null
            ? request
            : request with { Permissions = request.Permissions.Order(StringComparer.Ordinal).ToList() };
        return _http.SendAsync<Delegation>(HttpMethod.Post, "v1/delegations", body, ct, retry: false);
    }

    public Task<Delegation> GetDelegationAsync(string delegationId, CancellationToken ct = default) =>
        _http.SendAsync<Delegation>(HttpMethod.Get, $"v1/delegations/{HttpTransport.Seg(delegationId)}", null, ct);

    public async Task RevokeDelegationAsync(string delegationId, CancellationToken ct = default)
    {
        using var _ = await _http.SendRawAsync(
            HttpMethod.Delete, $"v1/delegations/{HttpTransport.Seg(delegationId)}", null, ct).ConfigureAwait(false);
    }

    /// <summary>Kill switch: revoke every active grant of a tenant / user / agent. Returns the count.</summary>
    public async Task<int> RevokeDelegationsAsync(
        RevokeDelegationsRequest request, CancellationToken ct = default)
    {
        var response = await _http.SendAsync<RevokeResponse>(
            HttpMethod.Post, "v1/delegations/revoke", request, ct).ConfigureAwait(false);
        return response.Revoked;
    }

    public Task<DelegationIntrospection> IntrospectDelegationAsync(
        string token, CancellationToken ct = default) =>
        _http.SendAsync<DelegationIntrospection>(
            HttpMethod.Post, "v1/delegations/introspect", new { token }, ct);

    public void Dispose() => _http.Dispose();

    // ---- Internals ------------------------------------------------------------

    private static readonly IReadOnlyDictionary<string, object?> Empty = new Dictionary<string, object?>();

    private static AuthorizeRequest WithContext(AuthorizeRequest r) =>
        r.Context is null ? r with { Context = Empty } : r;

    private static string CacheKey(EffectivePermissionsRequest r)
    {
        var s = r.Subject;
        var sb = new StringBuilder()
            .Append(r.TenantId).Append('|').Append(r.ApplicationId).Append('|')
            .Append(s.Type).Append(':').Append(s.UserId).Append(':').Append(s.AgentId)
            .Append(':').Append(s.ServiceAccountId).Append(':')
            .Append(s.UserRef is null ? "" : $"{s.UserRef.Provider}\u001f{s.UserRef.Issuer}\u001f{s.UserRef.Subject}")
            .Append(':').Append(s.AgentName);
        if (!string.IsNullOrEmpty(r.DelegationToken))
        {
            // A grant narrows the set, so it must partition the cache too.
            var hash = SHA256.HashData(Encoding.UTF8.GetBytes(r.DelegationToken));
            sb.Append(":d=").Append(Convert.ToHexString(hash)[..24]);
        }
        return sb.ToString();
    }

    private bool TryGetCached(string key, out IReadOnlySet<string> permissions)
    {
        lock (_cacheLock)
        {
            if (_cache.TryGetValue(key, out var node))
            {
                if (node.Value.ExpiresAt > _clock.GetUtcNow())
                {
                    _lru.Remove(node);
                    _lru.AddLast(node);
                    permissions = new HashSet<string>(node.Value.Permissions, StringComparer.Ordinal);
                    return true;
                }
                _lru.Remove(node);
                _cache.Remove(key);
            }
        }
        permissions = null!;
        return false;
    }

    private void Put(string key, string tenantId, string applicationId, HashSet<string> permissions)
    {
        var entry = new CacheEntry(key, tenantId, applicationId, permissions, _clock.GetUtcNow() + _cacheTtl);
        lock (_cacheLock)
        {
            if (_cache.Remove(key, out var old))
            {
                _lru.Remove(old);
            }
            _cache[key] = _lru.AddLast(entry);
            while (_cache.Count > _cacheMax && _lru.First is { } oldest)
            {
                _lru.RemoveFirst();
                _cache.Remove(oldest.Value.Key);
            }
        }
    }

    private sealed record BulkResponse
    {
        public IReadOnlyList<BulkCheckResult> Results { get; init; } = [];
    }

    private sealed record PermissionsResponse
    {
        public IReadOnlyList<string> Permissions { get; init; } = [];
    }

    private sealed record RevokeResponse
    {
        public int Revoked { get; init; }
    }
}
