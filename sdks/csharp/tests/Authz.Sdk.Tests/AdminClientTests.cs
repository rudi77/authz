using System.Text.Json;
using Xunit;

namespace Authz.Sdk.Tests;

public class AdminClientTests
{
    private static AuthzAdminClient NewAdmin(MockHandler h) => new(new AuthzAdminClientOptions
    {
        BaseUrl = "http://authz.test/base",
        ApiKey = "admin",
        HttpClient = h.Client(),
    });

    [Fact]
    public async Task CreateTenant_PostsBody_UnderBasePath()
    {
        var h = new MockHandler(_ => (201, """{"id": "t1", "slug": "acme", "name": "Acme", "status": "active"}"""));
        using var admin = NewAdmin(h);

        var tenant = await admin.CreateTenantAsync("acme", "Acme");

        Assert.Equal("t1", tenant.Id);
        var r = h.Requests[0];
        Assert.Equal("/base/v1/tenants", r.PathAndQuery);
        Assert.Equal("admin", r.ApiKey);
        Assert.Equal("""{"slug":"acme","name":"Acme","status":"active"}""", r.Body);
    }

    [Fact]
    public async Task UpsertRole_ReusesExistingRole_AndSetsPermissions()
    {
        var h = new MockHandler(r => r.Method == HttpMethod.Get
            ? (200, """[{"id": "r1", "name": "editor", "scope": "application", "application_id": "a", "tenant_id": null, "description": null, "is_system": false}]""")
            : (200, "{}"));
        using var admin = NewAdmin(h);

        var role = await admin.UpsertRoleWithPermissionsAsync("a", "editor", ["docs.read", "docs.write"]);

        Assert.Equal("r1", role.Id);
        Assert.Null(role.TenantId);
        Assert.Equal(2, h.Calls);
        Assert.Equal(HttpMethod.Put, h.Requests[1].Method);
        Assert.Equal("/base/v1/roles/r1/permissions", h.Requests[1].PathAndQuery);
        Assert.Equal("""{"permissions":["docs.read","docs.write"]}""", h.Requests[1].Body);
    }

    [Fact]
    public async Task Memberships_And_Agents()
    {
        const string membership =
            """{"id": "m1", "tenant_id": "t", "user_id": "u", "roles": ["editor"], "status": "active"}""";
        const string agentJson =
            """{"id": "ag", "tenant_id": "t", "application_id": "a", "name": "bot", "role": "", "status": "active"}""";
        var h = new MockHandler(r => r.PathAndQuery switch
        {
            var p when p.Contains("/memberships?") => (200, $"[{membership}]"),
            var p when p.EndsWith("/memberships") => (201, membership),
            var p when p.EndsWith("/agents") => (201, agentJson),
            _ => (204, ""),
        });
        using var admin = NewAdmin(h);

        var m = await admin.CreateMembershipAsync("t", "u", roles: ["editor"]);
        var list = await admin.ListMembershipsAsync("t", page: 2, pageSize: 10);
        var agent = await admin.CreateAgentAsync("t", "a", "bot");
        await admin.SetAgentRolesAsync(agent.Id, ["reader"]);

        Assert.Equal(["editor"], m.Roles);
        Assert.Single(list);
        Assert.Equal("/base/v1/tenants/t/memberships?page=2&page_size=10", h.Requests[1].PathAndQuery);
        using var body = JsonDocument.Parse(h.Requests[0].Body!);
        Assert.Equal("u", body.RootElement.GetProperty("user_id").GetString());
        Assert.False(body.RootElement.TryGetProperty("application_id", out _));
        Assert.Equal("/base/v1/agents/ag/roles", h.Requests[3].PathAndQuery);
    }

    [Fact]
    public async Task AdminWrites_AreNotRetriedByDefault()
    {
        var h = new MockHandler(_ => (502, "bad gateway"));
        using var admin = NewAdmin(h);

        await Assert.ThrowsAsync<AuthzServiceException>(() => admin.CreateApplicationAsync("app", "App"));
        Assert.Equal(1, h.Calls);
    }
}
