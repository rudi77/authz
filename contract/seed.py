"""Seed the contract fixture: application ``dtm`` with a management and a runtime client.

Run by the ``seed`` service of ``docker-compose.contract.yml`` (or by hand
against any authz with the Authorization Server enabled)::

    python contract/seed.py --url http://localhost:18080 --admin-key contract-operator-key

1. Registers two OAuth clients with the operator key: ``dtm-management``
   (scope ``admin``) and ``dtm-runtime`` (scope ``runtime``).
2. The management client creates application ``dtm`` through
   ``PUT /v1/applications/dtm/catalog`` and thereby becomes its manager
   (``managed_by``).
3. Writes both credentials to ``--out`` (default ``contract/.secrets``).

Idempotent: when ``dtm`` already exists and the stored management client
still gets a token, nothing is changed.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

import httpx

APP = "dtm"


def _wait_healthy(client: httpx.Client, timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while True:
        try:
            if client.get("/healthz").status_code == 200:
                return
        except httpx.TransportError:
            pass
        if time.monotonic() > deadline:
            sys.exit(f"authz not healthy after {timeout:.0f}s")
        time.sleep(1)


def _token(client: httpx.Client, creds: dict) -> str | None:
    r = client.post(
        "/oauth/token",
        data={"grant_type": "client_credentials"},
        auth=(creds["client_id"], creds["client_secret"]),
    )
    return r.json()["access_token"] if r.status_code == 200 else None


def _register(client: httpx.Client, admin: dict, name: str, scope: str) -> dict:
    r = client.post("/v1/oauth/clients", json={"name": name, "scopes": [scope]}, headers=admin)
    r.raise_for_status()
    body = r.json()
    return {"client_id": body["client_id"], "client_secret": body["client_secret"], "scope": scope}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", required=True, help="authz base URL as seen by the seed")
    parser.add_argument("--admin-key", required=True, help="operator (bootstrap) API key")
    parser.add_argument(
        "--public-url", help="base URL consumers use (written to the secret files)"
    )
    parser.add_argument("--out", default=str(Path(__file__).parent / ".secrets"))
    parser.add_argument("--timeout", type=float, default=60.0)
    args = parser.parse_args()

    out = Path(args.out)
    public_url = (args.public_url or args.url).rstrip("/")
    admin = {"X-API-Key": args.admin_key}

    with httpx.Client(base_url=args.url, timeout=10.0) as client:
        _wait_healthy(client, args.timeout)

        existing = out / "management.json"
        app_exists = client.get(f"/v1/applications/{APP}", headers=admin).status_code == 200
        if app_exists and existing.exists() and _token(client, json.loads(existing.read_text())):
            print(f"authz contract fixture already seeded; credentials in {out}")
            return
        if app_exists:
            sys.exit(
                f"application '{APP}' exists but {existing} is missing or stale; "
                "start from a fresh database (docker compose down, then up)"
            )

        management = _register(client, admin, "dtm-management", "admin")
        runtime = _register(client, admin, "dtm-runtime", "runtime")

        token = _token(client, management)
        if token is None:
            sys.exit("management client could not obtain a token")
        r = client.put(
            f"/v1/applications/{APP}/catalog",
            json={"name": "Digital Teammates", "permissions": [], "default_roles": []},
            headers={"Authorization": f"Bearer {token}"},
        )
        r.raise_for_status()
        app = client.get(f"/v1/applications/{APP}", headers=admin).json()

    out.mkdir(parents=True, exist_ok=True)
    for name, creds in (("management", management), ("runtime", runtime)):
        payload = {
            **creds,
            "base_url": public_url,
            "token_url": f"{public_url}/oauth/token",
            "application": APP,
        }
        (out / f"{name}.json").write_text(json.dumps(payload, indent=2) + "\n")
    print(
        f"seeded application '{APP}' ({app['id']}), managed_by={app.get('managed_by')}; "
        f"credentials in {out}"
    )


if __name__ == "__main__":
    main()
