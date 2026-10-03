"""One delegated agent run against a local authz service.

Requires a running service with the admin key dev-key, for example the
single container from the getting-started guide. Each run creates its own
tenant and application, so the script can be repeated.
"""

import secrets

from authz_sdk import AuthzAdminClient, AuthzClient, Subject
from authz_sdk.agent_session import delegation_claims

URL, ADMIN_KEY = "http://localhost:8080", "dev-key"
IDP = {"provider": "generic_oidc", "issuer": "https://idp.example.com", "subject": "alice"}
ACTIONS = ("read", "review", "approve")
suffix = secrets.token_hex(3)

# --- Set up: one lawyer, one assistant agent -------------------------------
admin = AuthzAdminClient(URL, api_key=ADMIN_KEY)
tenant = admin.create_tenant(slug=f"acme-{suffix}", name="ACME Corp")
app = admin.create_application(slug=f"contract-ai-{suffix}", name="Contract AI")
for action in ACTIONS:
    admin.create_permission(app.id, name=f"contracts.{action}")
admin.upsert_role_with_permissions(
    app.id, name="lawyer", permissions=[f"contracts.{a}" for a in ACTIONS])
admin.upsert_role_with_permissions(
    app.id, name="assistant", scope="agent",
    permissions=["contracts.read", "contracts.review"])

# Alice joins through an invitation, as a real user would.
invite = admin.create_invitation(
    tenant.id, email="alice@acme.example", application_id=app.id, roles=["lawyer"])
admin.accept_invitation(invite.token, **IDP)

agent = admin.create_agent(tenant.id, app.id, name="contract-assistant")
admin.set_agent_roles(agent.id, ["assistant"])
runtime_key = admin.issue_api_key(name=f"assistant-{suffix}", scopes=["runtime"]).key

# --- The application: Alice is signed in ------------------------------------
authz = AuthzClient(URL, api_key=runtime_key)
ctx = authz.resolve_context(application_id=app.slug, explicit_tenant_id=tenant.id, **IDP)
agent_for_alice = Subject(type="agent", user_id=ctx.user_id, agent_id=agent.id)


def decisions(token=None):
    out = {}
    for action in ACTIONS:
        r = authz.authorize_decision(
            tenant_id=ctx.tenant_id, application_id=ctx.application_id,
            subject=agent_for_alice, resource="contracts", action=action,
            delegation_token=token)
        out[action] = r.reason
    return out


print("1 agent, no grant:   ", decisions())

grant = authz.create_delegation(
    tenant_id=ctx.tenant_id, application_id=ctx.application_id,
    user_id=ctx.user_id, agent_id=agent.id,
    permissions={"contracts.read"}, ttl_seconds=900, purpose="Summarise NDA #42")
claims = delegation_claims(grant.token)
print("2 grant claims:      ", {k: claims[k] for k in ("permissions", "purpose")})
print("3 agent, with grant: ", decisions(grant.token))

# Alice loses her role while the grant is still valid.
membership = admin.list_memberships(tenant.id)[0]
admin.update_membership(membership.id, roles=[])
print("4 role removed:      ", decisions(grant.token))
admin.update_membership(membership.id, roles=["lawyer"])

# The kill switch ends every grant of this agent.
revoked = authz.revoke_delegations(tenant_id=ctx.tenant_id, agent_id=agent.id)
print(f"5 revoked {revoked} grant(s):", decisions(grant.token))
