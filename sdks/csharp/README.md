# AuthZ C# SDK

.NET client for the AuthZ service, with the same surface as the Python, Go and
TypeScript SDKs: `AuthzClient` for runtime decisions, `AuthzAdminClient` for
management, and `ToolGuard` / `McpGuard` for local enforcement against a
preloaded permission snapshot. Like the Python SDK it also wraps delegation
grants (`X-Delegation-Token`, issue / get / revoke / introspect).

Targets `net8.0`. No dependencies beyond the BCL (`System.Text.Json`).

```
src/Authz.Sdk/          the library
tests/Authz.Sdk.Tests/  xUnit tests against an in-memory HttpMessageHandler
```

## Build and test

```bash
cd sdks/csharp
dotnet build -warnaserror
dotnet test
```

## Runtime decisions

```csharp
using Authz.Sdk;

using var authz = new AuthzClient(new AuthzClientOptions
{
    BaseUrl = "https://authz.example.com",
    ApiKey = "…",                         // runtime-scoped key
    CacheTtl = TimeSpan.FromMinutes(5),   // effective-permissions cache; Zero disables it
});

// Single check
await authz.RequireAsync(new AuthorizeRequest
{
    TenantId = "tenant_123",
    ApplicationId = "contract-ai",
    Subject = Subject.User("user_123"),
    Resource = "documents",
    Action = "read",
});

// Structured decision (reason, required permission) for audits
var decision = await authz.AuthorizeAsync(request);

// Many checks, one round-trip; the subject is resolved once
var results = await authz.BulkAuthorizeAsync(new BulkAuthorizeRequest
{
    TenantId = "tenant_123",
    ApplicationId = "contract-ai",
    Subject = Subject.Agent("user_123", "agent_contract_reviewer"),
    Checks = [new("documents", "read"), new("tools.gmail", "send")],
});
```

`Subject` also accepts references instead of ids: `UserRef` (provider, issuer,
subject) for the user and `AgentName` for the agent.

## Agent runs

```csharp
var session = await authz.StartAgentSessionAsync(
    tenantId: "tenant_123", applicationId: "contract-ai",
    userId: "user_123", agentId: "agent_contract_reviewer");

session.Tools.Require("tools.gmail", "send");          // throws PermissionDeniedException
session.Mcp.IsAllowed("github", "create_issue");       // mcp.github.create_issue
var visible = session.Mcp.AllowedTools("github");      // filter the tool list for the model
```

The snapshot is effective permissions = user ∩ agent ∩ tenant mask: an agent
never gets more than the acting user.

## Delegation grants

```csharp
var grant = await authz.CreateDelegationAsync(new CreateDelegationRequest
{
    TenantId = "tenant_123",
    ApplicationId = "contract-ai",
    UserId = "user_123",
    AgentName = "contract-reviewer",
    Permissions = ["documents.read"],   // null = everything user ∩ agent allows
    TtlSeconds = 900,
    Purpose = "review NDA #42",
});

// In the agent runtime: tenant, application, user and agent come from the token.
var session = await authz.StartDelegatedAgentSessionAsync(grant.Token!);

await authz.RevokeDelegationAsync(grant.Id);
await authz.RevokeDelegationsAsync(new RevokeDelegationsRequest { TenantId = "tenant_123", UserId = "user_123" });
```

`AuthorizeRequest`, `BulkAuthorizeRequest` and `EffectivePermissionsRequest`
take an optional `DelegationToken`; it is sent as `X-Delegation-Token` and
partitions the permission cache. `DelegationClaims.Parse(token)` reads the
routing claims **without** verifying the signature; the service verifies on
every call.

## Admin

```csharp
using var admin = new AuthzAdminClient("https://authz.example.com", apiKey: "…"); // admin-scoped key

var tenant = await admin.CreateTenantAsync("acme", "Acme Corp");
var app = await admin.CreateApplicationAsync("contract-ai", "Contract AI");
await admin.CreatePermissionAsync(app.Id, "documents.read");
await admin.UpsertRoleWithPermissionsAsync(app.Id, "reader", ["documents.read"]);
await admin.CreateMembershipAsync(tenant.Id, "user_123", applicationId: app.Id, roles: ["reader"]);
var agent = await admin.CreateAgentAsync(tenant.Id, app.Id, "contract-reviewer");
await admin.SetAgentRolesAsync(agent.Id, ["reader"]);
```

## Behaviour

- **Errors**: non-2xx → `AuthzServiceException` (`StatusCode`, raw `Body`,
  parsed `Detail`, and `ErrorCode` from `{"detail": {"reason"|"error": …}}`).
  Transport failures after the last retry → `AuthzClientException`. Denials
  from `RequireAsync` and the guards → `PermissionDeniedException`.
- **Retries**: the runtime client retries transport errors, per-attempt
  timeouts and 5xx with exponential backoff (`MaxRetries` = 2, `RetryBackoff`
  = 100 ms); 4xx is never retried, nor is a cancellation by the caller.
  Issuing a delegation is never retried, so a 5xx cannot issue two grants.
  The admin client does not retry by default (`MaxRetries` = 0).
- **Cache**: bounded LRU (`CacheMaxEntries`, default 1024) keyed by tenant,
  application, subject and grant; thread-safe. Like the other SDKs it is
  eventually consistent: a revoked permission can be honoured for up to one
  TTL. Call `InvalidateCache(tenantId, applicationId)` after admin changes.
- **HttpClient**: pass your own (`HttpClient` option, e.g. from
  `IHttpClientFactory` or with mTLS); the SDK only disposes clients it
  created. Path segments (ids, slugs) are URL-escaped.

Not wrapped yet (as in Go / TypeScript): the declarative provisioning
endpoints (catalog, tenant state, tenant role overrides) and API key /
invitation management; call them over HTTP directly.
