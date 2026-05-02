"""Locust load test for the AuthZ runtime path.

Run against a deployed service::

    pip install locust
    AUTHZ_BASE_URL=http://localhost:8080 \\
    AUTHZ_API_KEY=dev-key \\
    AUTHZ_TENANT_ID=... \\
    AUTHZ_APPLICATION_ID=... \\
    AUTHZ_USER_ID=... \\
        locust -f loadtests/locustfile.py --host=$AUTHZ_BASE_URL

The seed task (``on_start``) only runs once per simulated user; it
intentionally **does not** create tenant/application/permissions so that
the load test isn't dominated by management traffic. Bootstrap with
``authz bootstrap`` first.
"""

from __future__ import annotations

import os
import random

from locust import HttpUser, between, task


class AuthzUser(HttpUser):
    wait_time = between(0.05, 0.2)

    def on_start(self) -> None:
        self.api_key = os.environ.get("AUTHZ_API_KEY", "dev-key")
        self.tenant_id = os.environ["AUTHZ_TENANT_ID"]
        self.application_id = os.environ["AUTHZ_APPLICATION_ID"]
        self.user_id = os.environ["AUTHZ_USER_ID"]
        self.client.headers["X-API-Key"] = self.api_key

    @task(weight=8)
    def authorize_single(self) -> None:
        resource = random.choice(["docs", "contracts", "invoices"])
        action = random.choice(["read", "review", "approve"])
        self.client.post(
            "/v1/authorize",
            json={
                "tenant_id": self.tenant_id,
                "application_id": self.application_id,
                "subject": {"type": "user", "user_id": self.user_id},
                "resource": resource,
                "action": action,
            },
            name="POST /v1/authorize",
        )

    @task(weight=4)
    def bulk_authorize(self) -> None:
        self.client.post(
            "/v1/bulk-authorize",
            json={
                "tenant_id": self.tenant_id,
                "application_id": self.application_id,
                "subject": {"type": "user", "user_id": self.user_id},
                "checks": [
                    {"resource": "docs", "action": "read"},
                    {"resource": "docs", "action": "write"},
                    {"resource": "tools.gmail", "action": "send"},
                ],
            },
            name="POST /v1/bulk-authorize",
        )

    @task(weight=2)
    def effective_permissions(self) -> None:
        self.client.post(
            "/v1/effective-permissions",
            json={
                "tenant_id": self.tenant_id,
                "application_id": self.application_id,
                "subject": {"type": "user", "user_id": self.user_id},
            },
            name="POST /v1/effective-permissions",
        )

    @task(weight=1)
    def healthz(self) -> None:
        self.client.get("/healthz", name="GET /healthz")
