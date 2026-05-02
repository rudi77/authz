"""Shared pytest fixtures.

Each test gets a fresh in-memory SQLite database; the FastAPI app is built
against that DB via an env-var override.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from collections.abc import Iterator

import pytest


@pytest.fixture()
def temp_db_url() -> Iterator[str]:
    fd, path = tempfile.mkstemp(prefix="authz-test-", suffix=".db")
    os.close(fd)
    url = f"sqlite+pysqlite:///{path}"
    yield url
    with contextlib.suppress(FileNotFoundError):
        os.unlink(path)
