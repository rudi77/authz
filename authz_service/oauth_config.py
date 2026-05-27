"""Parse AUTHZ_OAUTH_RESOURCE_ISSUERS / _FILE into :class:`IssuerConfig` list.

Expected JSON shape (array of objects, env var or file body)::

    [
      {
        "issuer": "https://login.microsoftonline.com/<tid>/v2.0",
        "audience": "api://authz",
        "jwks_url": null,
        "algorithms": ["RS256"],
        "scope_claim": "scp",
        "scope_separator": " ",
        "scope_map": {"AuthZ.Admin": "admin", "AuthZ.Runtime": "runtime"},
        "tenant_claim": "tid",
        "tenant_prefix": ""
      }
    ]

Read once at app startup — runtime hot-reload is deliberately omitted (see
plan, section A.6: issuer trust is operator-level, redeploy to change).
"""

from __future__ import annotations

import json
from pathlib import Path

from authz_service.config import Settings
from authzkit.security.oauth_resource import IssuerConfig


class OAuthConfigError(Exception):
    """Raised when issuer config is structurally invalid."""


def load_issuer_configs(settings: Settings) -> list[IssuerConfig]:
    """Return the configured issuer list, or an empty list if none configured."""
    raw = settings.oauth_resource_issuers_json.strip()
    if not raw and settings.oauth_resource_issuers_file:
        path = Path(settings.oauth_resource_issuers_file)
        if not path.exists():
            raise OAuthConfigError(
                f"AUTHZ_OAUTH_RESOURCE_ISSUERS_FILE not found: {path}"
            )
        raw = path.read_text(encoding="utf-8").strip()
    if not raw:
        return []
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OAuthConfigError(f"invalid OAuth issuer JSON: {exc}") from exc
    if not isinstance(payload, list):
        raise OAuthConfigError(
            "AUTHZ_OAUTH_RESOURCE_ISSUERS must be a JSON array of issuer objects"
        )
    configs: list[IssuerConfig] = []
    for idx, entry in enumerate(payload):
        if not isinstance(entry, dict):
            raise OAuthConfigError(f"issuer[{idx}] is not a JSON object")
        configs.append(_build_issuer(entry, idx))
    return configs


def _build_issuer(entry: dict, idx: int) -> IssuerConfig:
    issuer = entry.get("issuer")
    audience = entry.get("audience")
    if not issuer or not isinstance(issuer, str):
        raise OAuthConfigError(f"issuer[{idx}] missing 'issuer' string")
    if audience is None:
        raise OAuthConfigError(f"issuer[{idx}] missing 'audience'")
    if isinstance(audience, list):
        audience_value: str | tuple[str, ...] = tuple(str(a) for a in audience)
    else:
        audience_value = str(audience)
    algorithms = entry.get("algorithms") or ("RS256",)
    if isinstance(algorithms, str):
        algorithms = (algorithms,)
    return IssuerConfig(
        issuer=issuer,
        audience=audience_value,
        jwks_url=entry.get("jwks_url"),
        algorithms=tuple(str(a) for a in algorithms),
        leeway_seconds=int(entry.get("leeway_seconds", 30)),
        scope_claim=str(entry.get("scope_claim", "scope")),
        scope_separator=entry.get("scope_separator", " "),
        scope_map=dict(entry.get("scope_map") or {}),
        tenant_claim=entry.get("tenant_claim", "tid"),
        tenant_prefix=str(entry.get("tenant_prefix", "")),
    )
