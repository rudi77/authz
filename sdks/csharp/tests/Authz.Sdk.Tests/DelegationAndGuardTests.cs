using System.Text;
using System.Text.Json;
using Xunit;

namespace Authz.Sdk.Tests;

public class DelegationAndGuardTests
{
    private static AuthzClient NewClient(MockHandler h) => new(new AuthzClientOptions
    {
        BaseUrl = "http://authz.test/",
        ApiKey = "k",
        HttpClient = h.Client(),
        RetryBackoff = TimeSpan.FromMilliseconds(1),
    });

    private static string B64Url(string json) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static string FakeGrant() =>
        B64Url("""{"alg":"RS256"}""") + "." + B64Url("""
            {"jti": "d-1", "sub": "u", "act": {"sub": "ag"}, "exp": 1767225600,
             "authz": {"tenant_id": "t", "application_id": "a",
                       "permissions": ["docs.read", "mcp.github.create_issue"], "purpose": "triage"}}
            """) + ".sig";

    private const string DelegationJson = """
        {"id": "d-1", "tenant_id": "t", "application_id": "a", "user_id": "u", "agent_id": "ag",
         "permissions": ["docs.read"], "purpose": "triage", "issued_by": "key-1", "status": "active",
         "active": true, "expires_at": "2026-01-01T00:00:00Z", "revoked_at": null,
         "created_at": "2025-12-31T23:00:00Z", "token": "jwt"}
        """;

    [Fact]
    public async Task CreateDelegation_SendsSortedSubset_AndIsNotRetried()
    {
        var h = new MockHandler(_ => (200, DelegationJson));
        using var client = NewClient(h);

        var d = await client.CreateDelegationAsync(new CreateDelegationRequest
        {
            TenantId = "t",
            ApplicationId = "a",
            UserId = "u",
            AgentName = "contract-bot",
            Permissions = ["docs.write", "docs.read"],
            TtlSeconds = 600,
        });

        Assert.Equal("jwt", d.Token);
        Assert.Equal(new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero), d.ExpiresAt);
        Assert.Null(d.RevokedAt);
        var r = Assert.Single(h.Requests);
        Assert.Equal("/v1/delegations", r.PathAndQuery);
        using var body = JsonDocument.Parse(r.Body!);
        var root = body.RootElement;
        Assert.Equal(["docs.read", "docs.write"], root.GetProperty("permissions").EnumerateArray().Select(e => e.GetString()));
        Assert.Equal(600, root.GetProperty("ttl_seconds").GetInt32());
        Assert.Equal("contract-bot", root.GetProperty("agent_name").GetString());
        Assert.False(root.TryGetProperty("agent_id", out _));
        Assert.False(root.TryGetProperty("purpose", out _));

        var failing = new MockHandler(_ => (503, "{}"));
        using var failingClient = NewClient(failing);
        await Assert.ThrowsAsync<AuthzServiceException>(() => failingClient.CreateDelegationAsync(
            new CreateDelegationRequest { TenantId = "t", ApplicationId = "a", UserId = "u", AgentId = "ag" }));
        Assert.Equal(1, failing.Calls);
    }

    [Fact]
    public async Task ConflictOnInactiveAgent_ExposesErrorCode()
    {
        var h = new MockHandler(_ => (409, """{"detail": {"error": "agent_not_active"}}"""));
        using var client = NewClient(h);

        var e = await Assert.ThrowsAsync<AuthzServiceException>(() => client.CreateDelegationAsync(
            new CreateDelegationRequest { TenantId = "t", ApplicationId = "a", UserId = "u", AgentId = "ag" }));

        Assert.Equal(409, e.StatusCode);
        Assert.Equal("agent_not_active", e.ErrorCode);
    }

    [Fact]
    public async Task GetRevokeIntrospect_HitTheRightEndpoints()
    {
        var h = new MockHandler(r => r.PathAndQuery switch
        {
            "/v1/delegations/revoke" => (200, """{"revoked": 3}"""),
            "/v1/delegations/introspect" => (200, """{"active": false, "reason": "revoked", "jti": "d-1"}"""),
            _ when r.Method == HttpMethod.Delete => (204, ""),
            _ => (200, DelegationJson),
        });
        using var client = NewClient(h);

        var d = await client.GetDelegationAsync("d/1");
        await client.RevokeDelegationAsync("d-1");
        var count = await client.RevokeDelegationsAsync(new RevokeDelegationsRequest { TenantId = "t", UserId = "u" });
        var info = await client.IntrospectDelegationAsync("jwt");

        Assert.Equal("d-1", d.Id);
        Assert.Equal("/v1/delegations/d%2F1", h.Requests[0].PathAndQuery);
        Assert.Equal(HttpMethod.Delete, h.Requests[1].Method);
        Assert.Equal(3, count);
        Assert.False(info.Active);
        Assert.Equal("revoked", info.Reason);
        Assert.Equal("d-1", info.Extra["jti"].GetString());
        Assert.Equal("""{"token":"jwt"}""", h.Requests[3].Body);
    }

    [Fact]
    public void DelegationClaims_ParsesRoutingClaims()
    {
        var c = DelegationClaims.Parse(FakeGrant());

        Assert.Equal("d-1", c.DelegationId);
        Assert.Equal("t", c.TenantId);
        Assert.Equal("a", c.ApplicationId);
        Assert.Equal("u", c.UserId);
        Assert.Equal("ag", c.AgentId);
        Assert.Equal("triage", c.Purpose);
        Assert.Equal(2, c.Permissions.Count);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1767225600), c.ExpiresAt);
        Assert.Throws<AuthzClientException>(() => DelegationClaims.Parse("not-a-jwt"));
    }

    [Fact]
    public void ToolGuard_RequireRejectsMissingPermission()
    {
        var guard = new ToolGuard(["tools.gmail.send"]);

        Assert.True(guard.IsAllowed("tools.gmail", "send"));
        guard.Require("tools.gmail", "send");
        var e = Assert.Throws<PermissionDeniedException>(() => guard.Require("tools.gmail", "delete"));
        Assert.Equal("tools.gmail.delete", e.Permission);
    }

    [Fact]
    public void McpGuard_NamespacesUnderMcp_AndListsTools()
    {
        var guard = new McpGuard(["mcp.github.list_repos", "mcp.github.create_issue", "mcp.slack.post", "docs.read"]);

        Assert.True(guard.IsAllowed("github", "create_issue"));
        Assert.False(guard.IsAllowed("github", "delete_repo"));
        Assert.Equal(["create_issue", "list_repos"], guard.AllowedTools("github"));
        Assert.Throws<PermissionDeniedException>(() => guard.Require("slack", "delete"));
    }

    [Fact]
    public async Task StartAgentSession_YieldsWorkingGuards()
    {
        var h = new MockHandler(_ => (200, """{"permissions": ["docs.read", "mcp.github.create_issue"]}"""));
        using var client = NewClient(h);

        var session = await client.StartAgentSessionAsync("t", "a", "u", "ag");

        Assert.True(session.Tools.IsAllowed("docs", "read"));
        Assert.True(session.Mcp.IsAllowed("github", "create_issue"));
        Assert.False(session.Mcp.IsAllowed("github", "delete_repo"));
        using var body = JsonDocument.Parse(h.Requests[0].Body!);
        Assert.Equal("agent", body.RootElement.GetProperty("subject").GetProperty("type").GetString());
    }

    [Fact]
    public async Task StartDelegatedAgentSession_RoutesFromTokenAndSendsIt()
    {
        var h = new MockHandler(_ => (200, """{"permissions": ["docs.read"]}"""));
        using var client = NewClient(h);
        var token = FakeGrant();

        var session = await client.StartDelegatedAgentSessionAsync(token);

        Assert.Equal(token, session.DelegationToken);
        var r = Assert.Single(h.Requests);
        Assert.Equal(token, r.DelegationToken);
        using var body = JsonDocument.Parse(r.Body!);
        Assert.Equal("t", body.RootElement.GetProperty("tenant_id").GetString());
        Assert.Equal("ag", body.RootElement.GetProperty("subject").GetProperty("agent_id").GetString());
    }
}
