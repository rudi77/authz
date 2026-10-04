"""End-to-end check of the consumer deployment in deploy/docker-compose.yml.

Runs exactly the "first start" of deploy/README.md against a throwaway
Compose project (``authz-verify``) and tears it down again::

    python deploy/verify.py                      # build the image from this checkout
    python deploy/verify.py --image ghcr.io/rudi77/authz:v0.2.0   # check a published image
    python deploy/verify.py --keep               # leave the stack running for inspection

Needs Docker with Compose v2 and Python 3.11+ (standard library only).

Steps: build the image → generate a signing key with the image's own Python →
``compose up --wait`` (Postgres + authz, migrations via the entrypoint) →
create the management (``admin``) and runtime (``runtime``) clients with the
``authz`` CLI inside the container → from inside the network: tokens for both
clients, catalog PUT by the management client (it becomes ``managed_by``),
tenant state with one member and one agent, ``/v1/authorize`` with
references, a delegation grant (signing key on Postgres), and the 403s for
the operator key and the runtime client on the managed application →
``compose down -v``. Exit code 0 when every check passed.
"""

from __future__ import annotations

import argparse
import json
import os
import secrets
import subprocess
import sys
from pathlib import Path

DEPLOY = Path(__file__).resolve().parent
REPO = DEPLOY.parent
PROJECT = "authz-verify"
KEY_FILE = DEPLOY / "secrets" / "verify-signing-key.pem"

KEYGEN = """
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
print(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
      serialization.NoEncryption()).decode(), end="")
"""

# Runs inside the authz container (same network as a consumer would be).
CHECKS = r"""
import json, os, sys
import httpx

base = "http://authz:8080"
mgmt = json.loads(os.environ["VERIFY_MANAGEMENT"])
rt = json.loads(os.environ["VERIFY_RUNTIME"])
operator = {"X-API-Key": os.environ["VERIFY_OPERATOR_KEY"]}
failures = []

def check(name, ok, detail=""):
    print(("ok   " if ok else "FAIL ") + name + ("" if ok else f"  -> {detail}"))
    if not ok:
        failures.append(name)

c = httpx.Client(base_url=base, timeout=10.0)

def token(creds):
    r = c.post("/oauth/token", data={"grant_type": "client_credentials"},
               auth=(creds["client_id"], creds["client_secret"]))
    check(f"token for {creds['name']}", r.status_code == 200, r.text)
    return {"Authorization": "Bearer " + r.json().get("access_token", "")}

r = c.get("/healthz")
check("GET /healthz", r.status_code == 200, r.text)
r = c.get("/v1/applications", headers=operator)
check("bootstrap operator key works", r.status_code == 200, r.text)

manager = token(mgmt)
runtime = token(rt)

catalog = {
    "name": "Digital Teammates",
    "permissions": [{"name": "runs.start"}, {"name": "mcp.sap-prod.read"}],
    "default_roles": [{"name": "Operator", "permissions": ["runs.start", "mcp.sap-prod.read"]}],
}
r = c.put("/v1/applications/dtm/catalog", json=catalog, headers=manager)
check("catalog PUT by management client", r.status_code == 200, r.text)
app = c.get("/v1/applications/dtm", headers=operator).json()
check("management client is managed_by", app.get("managed_by") == "client:" + mgmt["client_id"],
      app)

tenant = "6f1c0000-0000-0000-0000-00000000a001"
ada = {"provider": "dtm", "issuer": "urn:dtm:verify", "subject": "ada"}
state = {
    "name": "ACME",
    "members": [{"user_ref": ada, "display_name": "Ada", "roles": ["Operator"]}],
    "agents": [{"name": "profile:invoice-agent", "permissions": ["mcp.sap-prod.read"]}],
}
r = c.put(f"/v1/applications/dtm/tenants/{tenant}/state", json=state, headers=manager)
check("tenant state PUT by management client", r.status_code == 200, r.text)

def authorize(subject, headers=runtime):
    return c.post("/v1/authorize", headers=headers, json={
        "tenant_id": tenant, "application_id": "dtm", "subject": subject,
        "resource": "mcp.sap-prod", "action": "read"})

r = authorize({"type": "user", "user_ref": ada})
check("authorize (runtime, user_ref) allowed", r.status_code == 200 and r.json()["allowed"],
      r.text)
agent = {"type": "agent", "user_ref": ada, "agent_name": "profile:invoice-agent"}
r = authorize(agent)
check("authorize (runtime, agent_name) allowed", r.status_code == 200 and r.json()["allowed"],
      r.text)
r = authorize({"type": "user", "user_ref": {**ada, "subject": "nobody"}})
check("authorize unknown user denies", r.status_code == 200 and not r.json()["allowed"], r.text)

r = c.post("/v1/delegations", headers=runtime, json={
    "tenant_id": tenant, "application_id": "dtm", "user_ref": ada,
    "agent_name": "profile:invoice-agent", "permissions": ["mcp.sap-prod.read"]})
check("delegation grant issued (signing key on Postgres)", r.status_code == 201, r.text)
if r.status_code == 201:
    r = authorize(agent, headers={**runtime, "X-Delegation-Token": r.json()["token"]})
    check("authorize with delegation token allowed", r.json().get("allowed") is True, r.text)

r = c.put("/v1/applications/dtm/catalog", json=catalog, headers=runtime)
check("runtime client cannot write the catalog", r.status_code == 403, r.text)
r = c.put("/v1/applications/dtm/catalog", json=catalog, headers=operator)
check("operator key gets application_managed_externally",
      r.status_code == 403 and r.json()["detail"].get("error") == "application_managed_externally",
      r.text)

sys.exit(1 if failures else 0)
"""


def _run(cmd: list[str], *, env=None, input_text=None, check=True) -> str:
    print("$ " + " ".join(cmd), flush=True)
    result = subprocess.run(
        cmd, env=env, input=input_text, capture_output=True, text=True, encoding="utf-8"
    )
    if check and result.returncode != 0:
        sys.stdout.write(result.stdout)
        sys.stderr.write(result.stderr)
        raise SystemExit(f"command failed ({result.returncode}): {' '.join(cmd)}")
    return result.stdout


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--image", help="use this image instead of building one")
    parser.add_argument("--keep", action="store_true", help="do not tear the stack down")
    args = parser.parse_args()
    sys.stdout.reconfigure(line_buffering=True)  # type: ignore[union-attr]

    image = args.image or "authz:deploy-verify"
    if not args.image:
        _run(["docker", "build", "-t", image, str(REPO)])

    KEY_FILE.parent.mkdir(parents=True, exist_ok=True)
    pem = _run(["docker", "run", "--rm", "--entrypoint", "python", image, "-c", KEYGEN])
    KEY_FILE.write_text(pem, encoding="utf-8")

    operator_key = secrets.token_urlsafe(24)
    env = {
        **os.environ,
        "AUTHZ_IMAGE": image,
        "AUTHZ_POSTGRES_PASSWORD": secrets.token_urlsafe(16),
        "AUTHZ_BOOTSTRAP_API_KEY": operator_key,
        "AUTHZ_OAUTH_ISSUER": "urn:authz:deploy-verify",
        "AUTHZ_SIGNING_KEY_FILE": str(KEY_FILE),
        "AUTHZ_NETWORK": PROJECT,
        "AUTHZ_REDIS_URL": "",
    }
    compose = ["docker", "compose", "-p", PROJECT, "-f", str(DEPLOY / "docker-compose.yml")]
    ok = False
    try:
        _run([*compose, "up", "-d", "--wait"], env=env)
        logs = _run([*compose, "logs", "authz"], env=env)
        if "applying database migrations" not in logs:
            raise SystemExit("entrypoint did not run the migrations:\n" + logs)
        print("ok   migrations applied by the entrypoint")

        creds = {}
        for name, scope in (("dtm-management", "admin"), ("dtm-runtime", "runtime")):
            out = _run(
                [*compose, "exec", "-T", "authz", "authz", "oauth", "client", "create",
                 "--name", name, "--scopes", scope],
                env=env,
            )
            creds[name] = json.loads(out)
            print(f"ok   client {name} ({scope}) created via CLI: {creds[name]['client_id']}")

        result = subprocess.run(
            [*compose, "exec", "-T",
             "-e", "VERIFY_MANAGEMENT=" + json.dumps(creds["dtm-management"]),
             "-e", "VERIFY_RUNTIME=" + json.dumps(creds["dtm-runtime"]),
             "-e", "VERIFY_OPERATOR_KEY=" + operator_key,
             "authz", "python", "-"],
            env=env, input=CHECKS, text=True, encoding="utf-8",
        )
        ok = result.returncode == 0
    finally:
        if args.keep:
            print(f"stack kept: docker compose -p {PROJECT} -f deploy/docker-compose.yml down -v")
        else:
            _run([*compose, "down", "-v"], env=env, check=False)
            KEY_FILE.unlink(missing_ok=True)
    print("deployment verification " + ("PASSED" if ok else "FAILED"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
