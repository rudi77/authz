using System.Text.Json;
using Xunit;

namespace Authz.Sdk.Tests;

public class ClientTests
{
    private const string Allow = """
        {"allowed": true, "decision": "allow", "reason": "permission_granted",
         "required_permission": "docs.read", "matched_permissions": ["docs.read"]}
        """;

    private const string Deny = """
        {"allowed": false, "decision": "deny", "reason": "missing_permission",
         "required_permission": "docs.write", "matched_permissions": []}
        """;

    private static AuthzClient NewClient(MockHandler h, TimeSpan? cacheTtl = null, TimeProvider? clock = null) =>
        new(new AuthzClientOptions
        {
            BaseUrl = "http://authz.test",
            ApiKey = "k",
            HttpClient = h.Client(),
            CacheTtl = cacheTtl ?? TimeSpan.Zero,
            RetryBackoff = TimeSpan.FromMilliseconds(1),
            TimeProvider = clock,
        });

    private static AuthorizeRequest Req(string action = "read", string? token = null) => new()
    {
        TenantId = "t",
        ApplicationId = "a",
        Subject = Subject.User("u"),
        Resource = "docs",
        Action = action,
        DelegationToken = token,
    };

    [Fact]
    public async Task Authorize_ReturnsAllowResult_AndSendsSnakeCase()
    {
        var h = new MockHandler(_ => (200, Allow));
        using var client = NewClient(h);

        var result = await client.AuthorizeAsync(Req());

        Assert.True(result.Allowed);
        Assert.Equal("docs.read", result.RequiredPermission);
        Assert.Equal(["docs.read"], result.MatchedPermissions);

        var r = Assert.Single(h.Requests);
        Assert.Equal(HttpMethod.Post, r.Method);
        Assert.Equal("/v1/authorize", r.PathAndQuery);
        Assert.Equal("k", r.ApiKey);
        Assert.Null(r.DelegationToken);
        using var body = JsonDocument.Parse(r.Body!);
        Assert.Equal("t", body.RootElement.GetProperty("tenant_id").GetString());
        Assert.Equal("user", body.RootElement.GetProperty("subject").GetProperty("type").GetString());
        Assert.Equal("u", body.RootElement.GetProperty("subject").GetProperty("user_id").GetString());
        Assert.False(body.RootElement.GetProperty("subject").TryGetProperty("agent_id", out _));
        Assert.Equal(JsonValueKind.Object, body.RootElement.GetProperty("context").ValueKind);
        Assert.False(body.RootElement.TryGetProperty("delegation_token", out _));
    }

    [Fact]
    public async Task Require_ThrowsPermissionDenied_WhenDenied()
    {
        var h = new MockHandler(_ => (200, Deny));
        using var client = NewClient(h);

        var e = await Assert.ThrowsAsync<PermissionDeniedException>(() => client.RequireAsync(Req("write")));
        Assert.Equal("docs.write", e.Permission);
    }

    [Fact]
    public async Task BulkAuthorize_ReturnsRows()
    {
        var h = new MockHandler(_ => (200, """
            {"results": [
              {"resource": "docs", "action": "read", "allowed": true, "reason": "permission_granted"},
              {"resource": "docs", "action": "delete", "allowed": false, "reason": "missing_permission"}]}
            """));
        using var client = NewClient(h);

        var rows = await client.BulkAuthorizeAsync(new BulkAuthorizeRequest
        {
            TenantId = "t",
            ApplicationId = "a",
            Subject = Subject.Agent("u", "ag"),
            Checks = [new BulkCheck("docs", "read"), new BulkCheck("docs", "delete")],
        });

        Assert.Equal(2, rows.Count);
        Assert.True(rows[0].Allowed);
        Assert.Equal("missing_permission", rows[1].Reason);
        using var body = JsonDocument.Parse(h.Requests[0].Body!);
        Assert.Equal("ag", body.RootElement.GetProperty("subject").GetProperty("agent_id").GetString());
        Assert.Equal(2, body.RootElement.GetProperty("checks").GetArrayLength());
    }

    [Fact]
    public async Task EffectivePermissions_CachesBySubject_UntilTtlExpires()
    {
        var h = new MockHandler(_ => (200, """{"permissions": ["docs.read", "tools.gmail.send"]}"""));
        var clock = new FakeClock();
        using var client = NewClient(h, TimeSpan.FromMinutes(1), clock);
        var req = new EffectivePermissionsRequest { TenantId = "t", ApplicationId = "a", Subject = Subject.User("u") };

        var first = await client.GetEffectivePermissionsAsync(req);
        var second = await client.GetEffectivePermissionsAsync(req);
        Assert.Equal(1, h.Calls);
        Assert.Contains("tools.gmail.send", second);
        Assert.NotSame(first, second);

        await client.GetEffectivePermissionsAsync(req with { Subject = Subject.User("other") });
        Assert.Equal(2, h.Calls);

        await client.GetEffectivePermissionsAsync(req with { BypassCache = true });
        Assert.Equal(3, h.Calls);

        clock.Now += TimeSpan.FromMinutes(2);
        await client.GetEffectivePermissionsAsync(req);
        Assert.Equal(4, h.Calls);
    }

    [Fact]
    public async Task EffectivePermissions_GrantPartitionsCache_AndIsSentAsHeader()
    {
        var h = new MockHandler(_ => (200, """{"permissions": ["docs.read"]}"""));
        using var client = NewClient(h, TimeSpan.FromMinutes(1));
        var req = new EffectivePermissionsRequest { TenantId = "t", ApplicationId = "a", Subject = Subject.Agent("u", "ag") };

        await client.GetEffectivePermissionsAsync(req);
        await client.GetEffectivePermissionsAsync(req with { DelegationToken = "grant-1" });
        await client.GetEffectivePermissionsAsync(req with { DelegationToken = "grant-1" });

        Assert.Equal(2, h.Calls);
        Assert.Null(h.Requests[0].DelegationToken);
        Assert.Equal("grant-1", h.Requests[1].DelegationToken);
    }

    [Fact]
    public async Task CacheKey_DelimitersInValues_DoNotCollide()
    {
        var h = new MockHandler(_ => (200, """{"permissions": []}"""));
        using var client = NewClient(h, TimeSpan.FromMinutes(1));
        Subject Ref(string subject, string agentName) => new()
        {
            Type = SubjectTypes.Agent,
            UserRef = new UserRef("entra", "https://iss", subject),
            AgentName = agentName,
        };
        var req = new EffectivePermissionsRequest { TenantId = "t", ApplicationId = "a", Subject = Ref("u:x", "y") };

        await client.GetEffectivePermissionsAsync(req);
        await client.GetEffectivePermissionsAsync(req with { Subject = Ref("u", "x:y") });
        await client.GetEffectivePermissionsAsync(req with { TenantId = "t|a", ApplicationId = "" });

        Assert.Equal(3, h.Calls);
    }

    [Fact]
    public async Task InvalidateCache_DropsMatchingPartitionOnly()
    {
        var h = new MockHandler(_ => (200, """{"permissions": []}"""));
        using var client = NewClient(h, TimeSpan.FromMinutes(1));
        var t1 = new EffectivePermissionsRequest { TenantId = "t1", ApplicationId = "a", Subject = Subject.User("u") };
        var t2 = t1 with { TenantId = "t2" };

        await client.GetEffectivePermissionsAsync(t1);
        await client.GetEffectivePermissionsAsync(t2);
        client.InvalidateCache(tenantId: "t1");
        await client.GetEffectivePermissionsAsync(t1);
        await client.GetEffectivePermissionsAsync(t2);

        Assert.Equal(3, h.Calls);
    }

    [Fact]
    public async Task Cache_EvictsLeastRecentlyUsed()
    {
        var h = new MockHandler(_ => (200, """{"permissions": []}"""));
        using var client = new AuthzClient(new AuthzClientOptions
        {
            BaseUrl = "http://authz.test",
            HttpClient = h.Client(),
            CacheTtl = TimeSpan.FromMinutes(1),
            CacheMaxEntries = 2,
        });
        EffectivePermissionsRequest R(string u) =>
            new() { TenantId = "t", ApplicationId = "a", Subject = Subject.User(u) };

        await client.GetEffectivePermissionsAsync(R("a"));
        await client.GetEffectivePermissionsAsync(R("b"));
        await client.GetEffectivePermissionsAsync(R("a")); // hit; "b" is now oldest
        await client.GetEffectivePermissionsAsync(R("c")); // evicts "b"
        Assert.Equal(3, h.Calls);

        await client.GetEffectivePermissionsAsync(R("a"));
        Assert.Equal(3, h.Calls);
        await client.GetEffectivePermissionsAsync(R("b"));
        Assert.Equal(4, h.Calls);
    }

    [Fact]
    public async Task Retries_On5xx_ThenSucceeds()
    {
        var attempts = 0;
        var h = new MockHandler(_ => ++attempts < 3 ? (503, """{"detail": "busy"}""") : (200, Allow));
        using var client = NewClient(h);

        var result = await client.AuthorizeAsync(Req());

        Assert.True(result.Allowed);
        Assert.Equal(3, h.Calls);
    }

    [Fact]
    public async Task ClientError_SurfacesServiceException_WithoutRetry()
    {
        var h = new MockHandler(_ => (403, """{"detail": {"reason": "tenant_scope_mismatch"}}"""));
        using var client = NewClient(h);

        var e = await Assert.ThrowsAsync<AuthzServiceException>(() => client.AuthorizeAsync(Req()));

        Assert.Equal(403, e.StatusCode);
        Assert.Equal("tenant_scope_mismatch", e.ErrorCode);
        Assert.Contains("tenant_scope_mismatch", e.Body);
        Assert.Equal(1, h.Calls);
    }

    [Fact]
    public async Task Redirect_IsNotTreatedAsSuccess()
    {
        var h = new MockHandler(_ => (302, ""));
        using var client = NewClient(h);

        var e = await Assert.ThrowsAsync<AuthzServiceException>(() => client.AuthorizeAsync(Req()));

        Assert.Equal(302, e.StatusCode);
        Assert.Equal(1, h.Calls);
    }

    [Fact]
    public async Task PersistentServerError_SurfacesAfterRetries()
    {
        var h = new MockHandler(_ => (500, "oops"));
        using var client = NewClient(h);

        var e = await Assert.ThrowsAsync<AuthzServiceException>(() => client.AuthorizeAsync(Req()));

        Assert.Equal(500, e.StatusCode);
        Assert.Null(e.Detail);
        Assert.Equal(3, h.Calls); // 1 + MaxRetries (2)
    }

    [Fact]
    public async Task TransportError_IsRetried_ThenWrapped()
    {
        var h = new MockHandler(_ => throw new HttpRequestException("connection refused"));
        using var client = NewClient(h);

        var e = await Assert.ThrowsAsync<AuthzClientException>(() => client.AuthorizeAsync(Req()));

        Assert.IsType<HttpRequestException>(e.InnerException);
        Assert.Equal(3, h.Calls);
    }

    [Fact]
    public async Task CallerCancellation_IsNotRetried()
    {
        using var cts = new CancellationTokenSource();
        var h = new MockHandler(_ =>
        {
            cts.Cancel();
            cts.Token.ThrowIfCancellationRequested();
            return (200, Allow);
        });
        using var client = NewClient(h);

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.AuthorizeAsync(Req(), cts.Token));
        Assert.Equal(1, h.Calls);
    }

    [Fact]
    public async Task ResolveContext_MapsResponse()
    {
        var h = new MockHandler(_ => (200, """
            {"tenant_id": "t", "application_id": "a", "user_id": "u",
             "roles": ["editor"], "permissions": ["docs.read"]}
            """));
        using var client = NewClient(h);

        var ctx = await client.ResolveContextAsync(new ResolveContextRequest
        {
            ApplicationId = "a",
            Provider = "entra",
            Issuer = "https://login.example",
            Subject = "oid-1",
            ExternalTenantId = "ext-1",
            Claims = new Dictionary<string, object?> { ["groups"] = new[] { "g1" } },
        });

        Assert.Equal("u", ctx.UserId);
        Assert.Equal(["editor"], ctx.Roles);
        using var body = JsonDocument.Parse(h.Requests[0].Body!);
        Assert.Equal("ext-1", body.RootElement.GetProperty("external_tenant_id").GetString());
        Assert.Equal("g1", body.RootElement.GetProperty("claims").GetProperty("groups")[0].GetString());
    }

    [Fact]
    public async Task SubjectReferences_AreSerialized()
    {
        var h = new MockHandler(_ => (200, Allow));
        using var client = NewClient(h);

        await client.AuthorizeAsync(Req() with
        {
            Subject = new Subject
            {
                Type = SubjectTypes.Agent,
                UserRef = new UserRef("entra", "https://iss", "oid-1"),
                AgentName = "contract-bot",
            },
        });

        using var body = JsonDocument.Parse(h.Requests[0].Body!);
        var subject = body.RootElement.GetProperty("subject");
        Assert.Equal("oid-1", subject.GetProperty("user_ref").GetProperty("subject").GetString());
        Assert.Equal("contract-bot", subject.GetProperty("agent_name").GetString());
    }

    [Fact]
    public void BaseUrl_IsRequired()
    {
        Assert.Throws<ArgumentException>(() => new AuthzClient(""));
    }
}
