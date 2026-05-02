"""Tests for the ``authz`` CLI bootstrap path.

Skipped when pyyaml is unavailable; the CLI uses YAML for the spec.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from authz_service.config import Settings, override_settings
from authz_service.dependencies import reset_engine

pytest.importorskip("yaml")


@pytest.fixture()
def running_app(temp_db_url):
    override_settings(
        Settings(
            database_url=temp_db_url,
            api_keys=("k1",),
            log_level="WARNING",
            audit_all_decisions=False,
            auto_provision_user=True,
            auto_provision_tenant=False,
        )
    )
    reset_engine()
    from authz_service.main import create_app

    return TestClient(create_app())


def test_bootstrap_against_in_process_app(running_app, tmp_path: Path, monkeypatch):
    spec = {
        "tenant": {
            "slug": "boot",
            "name": "Boot",
            "mappings": [
                {
                    "provider": "azure_entra",
                    "issuer": "https://login.example",
                    "external_tenant_id": "ext-1",
                }
            ],
            "feature_flags": {"github_mcp_enabled": True},
        },
        "application": {
            "slug": "boot-app",
            "name": "Boot App",
            "permissions": ["docs.read", "docs.write"],
            "roles": [
                {
                    "name": "reader",
                    "scope": "application",
                    "permissions": ["docs.read"],
                }
            ],
        },
    }
    spec_path = tmp_path / "spec.json"
    spec_path.write_text(json.dumps(spec))

    # Run the CLI's bootstrap in-process (avoids spawning a subprocess that
    # would need an actual server). We swap the AuthzAdminClient's HTTP
    # transport to the TestClient.
    from authz_sdk.admin import AuthzAdminClient
    from authz_service import cli

    monkeypatch.setattr(
        cli, "_admin_client", lambda args: AuthzAdminClient(
            base_url="http://testserver", api_key="k1", http_client=running_app
        ),
    )

    parser = cli.build_parser()
    args = parser.parse_args(["bootstrap", "--spec", str(spec_path)])
    args.func(args)

    # Verify by hitting the same TestClient.
    tenant = running_app.get(
        "/v1/tenants/boot", headers={"X-API-Key": "k1"}
    ).json()
    assert tenant["slug"] == "boot"
    running_app.get(
        f"/v1/applications/{tenant['id']}/permissions",
        headers={"X-API-Key": "k1"},
    )
    # The response above is keyed by application_id, not tenant_id; fix.
    app = running_app.get(
        "/v1/applications/boot-app", headers={"X-API-Key": "k1"}
    ).json()
    perms = running_app.get(
        f"/v1/applications/{app['id']}/permissions",
        headers={"X-API-Key": "k1"},
    ).json()
    assert sorted(p["name"] for p in perms) == ["docs.read", "docs.write"]


def test_cli_health_subcommand(running_app, monkeypatch):
    """The ``inspect health`` command uses httpx.get directly, not the SDK.

    We monkeypatch httpx.get to route through TestClient instead of trying
    to bind a real port.
    """
    from authz_service import cli

    def _fake_get(url, *args, **kwargs):
        # url is "http://localhost:8080/healthz" — extract path and run
        # against TestClient.
        from urllib.parse import urlparse

        path = urlparse(url).path or "/healthz"
        return running_app.get(path)

    monkeypatch.setattr(cli.httpx, "get", _fake_get)
    parser = cli.build_parser()
    args = parser.parse_args(["inspect", "health"])
    with pytest.raises(SystemExit) as exc:
        args.func(args)
    assert exc.value.code == 0
