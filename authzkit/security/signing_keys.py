"""RSA signing keys for the Authorization-Server-issued JWTs.

Bootstrap precedence (resolved at first call to :meth:`SigningKeyService.active_signing_key`):

1. ``AUTHZ_OAUTH_SIGNING_KEY_PEM`` environment variable. Treated as a
   long-lived operator-supplied key; the kid is derived from the PEM hash
   so reloads with the same material are idempotent.
2. DB-backed ``oauth_signing_keys`` table — a row with ``status='active'``.
3. Dev-mode + SQLite-only fallback: auto-generate an ephemeral 2048-bit
   RSA key and persist it. Refused on any non-SQLite DSN so we never write
   a freshly-minted private key into a production Postgres without the
   operator opting in.
4. Otherwise raise :class:`SigningKeyError` — fail closed at startup.

JWKS is the *union* of ``active`` and ``retiring`` keys, so previously-issued
tokens keep validating until they expire after a rotation.
"""

from __future__ import annotations

import base64
import hashlib
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

_log = logging.getLogger("authz.signing_keys")


class SigningKeyError(Exception):
    """Raised when no signing key can be resolved or material is malformed."""


@dataclass(frozen=True)
class SigningKey:
    """A loaded RSA signing key plus its JWKS metadata."""

    kid: str
    alg: str
    status: str  # active | retiring | revoked
    private_pem: str
    public_jwk: dict[str, Any]
    created_at: datetime | None = None


def _b64url_uint(value: int) -> str:
    """RFC 7518 §6.3 base64url-encode an unsigned integer (n, e)."""
    raw = value.to_bytes((value.bit_length() + 7) // 8 or 1, "big")
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _generate_rsa_keypair() -> tuple[str, dict[str, Any]]:
    """Generate a fresh RSA-2048 keypair, return (pem, public_jwk).

    Lazy ``cryptography`` import so the dependency only loads when the AS
    role is actually wired up — RS-only deployments skip it entirely.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = private.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("ascii")
    public_numbers = private.public_key().public_numbers()
    kid = _derive_kid(pem)
    jwk = {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(public_numbers.n),
        "e": _b64url_uint(public_numbers.e),
    }
    return pem, jwk


def _public_jwk_from_pem(pem: str, kid: str) -> dict[str, Any]:
    """Re-derive the JWK from a stored PEM (used when loading an env-supplied key)."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.rsa import RSAPrivateKey

    key = serialization.load_pem_private_key(pem.encode("ascii"), password=None)
    if not isinstance(key, RSAPrivateKey):
        raise SigningKeyError("AUTHZ_OAUTH_SIGNING_KEY_PEM must be an RSA private key")
    public_numbers = key.public_key().public_numbers()
    return {
        "kty": "RSA",
        "use": "sig",
        "alg": "RS256",
        "kid": kid,
        "n": _b64url_uint(public_numbers.n),
        "e": _b64url_uint(public_numbers.e),
    }


def _derive_kid(pem: str) -> str:
    """Stable kid from PEM material (sha256 prefix).

    Two boots with the same env-supplied PEM produce the same kid so cached
    consumers (JWKS clients) don't see a phantom rotation on every restart.
    """
    return hashlib.sha256(pem.encode("ascii")).hexdigest()[:16]


class SigningKeyService:
    """Manages active + retiring signing keys for the Authorization Server."""

    def __init__(
        self,
        store: Any,
        *,
        env_pem: str = "",
        dev_mode: bool = False,
        database_url: str = "",
    ) -> None:
        self.store = store
        self._env_pem = env_pem.strip()
        self._dev_mode = dev_mode
        self._database_url = database_url
        self._cached: SigningKey | None = None

    # ----- lookup / bootstrap ------------------------------------------------

    def active_signing_key(self) -> SigningKey:
        """Return the key to sign new tokens with; bootstrap if needed."""
        if self._cached is not None:
            return self._cached
        if self._env_pem:
            self._cached = self._load_env_key()
            return self._cached
        db_key = self._load_db_active()
        if db_key is not None:
            self._cached = db_key
            return db_key
        if self._dev_mode and self._database_url.startswith("sqlite"):
            _log.warning(
                "AUTHZ_OAUTH_SIGNING_KEY_PEM not set and no DB key found; "
                "generating ephemeral RSA-2048 key (dev mode + SQLite only)."
            )
            generated = self._generate_and_persist()
            self._cached = generated
            return generated
        raise SigningKeyError(
            "No OAuth signing key available. Set AUTHZ_OAUTH_SIGNING_KEY_PEM "
            "or run `authz oauth signing-key generate`."
        )

    def _load_env_key(self) -> SigningKey:
        kid = _derive_kid(self._env_pem)
        jwk = _public_jwk_from_pem(self._env_pem, kid)
        return SigningKey(
            kid=kid,
            alg="RS256",
            status="active",
            private_pem=self._env_pem,
            public_jwk=jwk,
        )

    def _load_db_active(self) -> SigningKey | None:
        from sqlalchemy import select

        from authzkit.storage import orm

        with self.store.session() as s:
            # ``ORDER BY created_at DESC LIMIT 1`` is defence in depth — the
            # schema enforces a single ``active`` row, but if invariants ever
            # slip (manual SQL, botched rotation, restore-mid-rotation) we
            # pick the newest deterministically instead of raising
            # MultipleResultsFound.
            row = s.scalars(
                select(orm.OAuthSigningKey)
                .where(orm.OAuthSigningKey.status == "active")
                .order_by(orm.OAuthSigningKey.created_at.desc())
                .limit(1)
            ).first()
            if row is None:
                return None
            return _row_to_signing_key(row)

    def _generate_and_persist(self) -> SigningKey:
        from authzkit.storage import orm

        pem, jwk = _generate_rsa_keypair()
        kid = jwk["kid"]
        with self.store.session() as s:
            row = orm.OAuthSigningKey(
                kid=kid,
                alg="RS256",
                public_jwk=jwk,
                private_pem=pem,
                status="active",
            )
            s.add(row)
            s.commit()
            return _row_to_signing_key(row)

    # ----- JWKS export ------------------------------------------------------

    def all_public_jwks(self) -> dict[str, Any]:
        """Public JWKs for ``/.well-known/jwks.json``: active + retiring + env."""
        from sqlalchemy import select

        from authzkit.storage import orm

        keys: list[dict[str, Any]] = []
        seen_kids: set[str] = set()
        # Env-supplied key first (operator's source of truth).
        if self._env_pem:
            env_key = self._load_env_key()
            keys.append(env_key.public_jwk)
            seen_kids.add(env_key.kid)
        with self.store.session() as s:
            rows = s.scalars(
                select(orm.OAuthSigningKey).where(
                    orm.OAuthSigningKey.status.in_(("active", "retiring"))
                )
            ).all()
            for row in rows:
                if row.kid in seen_kids:
                    continue
                keys.append(dict(row.public_jwk))
                seen_kids.add(row.kid)
        return {"keys": keys}

    # ----- rotation ---------------------------------------------------------

    def rotate(self) -> SigningKey:
        """Generate a new active key; demote the current active to retiring.

        Env-supplied keys are not rotatable through this API — flipping
        them requires re-deploying with a new ``AUTHZ_OAUTH_SIGNING_KEY_PEM``.
        Raises in that case so operators see the actual constraint.

        Concurrent rotation safety: on Postgres we take a row-level lock
        (``SELECT … FOR UPDATE``) on the current active row before
        demoting it, so two simultaneous rotations serialize cleanly
        instead of producing two active rows. SQLite ignores the lock
        hint and serializes via its database-level write lock, which is
        equivalent for the single-writer case.

        Defence in depth: the schema's partial unique index
        ``(status) WHERE status='active'`` (added in migration 0003)
        causes the second INSERT to fail loudly if the lock is somehow
        bypassed.
        """
        if self._env_pem:
            raise SigningKeyError(
                "Active signing key is supplied via AUTHZ_OAUTH_SIGNING_KEY_PEM; "
                "rotate it by deploying a new value."
            )
        from sqlalchemy import select

        from authzkit.storage import orm

        with self.store.session() as s:
            stmt = (
                select(orm.OAuthSigningKey)
                .where(orm.OAuthSigningKey.status == "active")
                .order_by(orm.OAuthSigningKey.created_at.desc())
                .with_for_update()
            )
            current = s.scalars(stmt).first()
            if current is not None:
                current.status = "retiring"
                current.rotated_at = datetime.now(UTC)
                # Flush so the partial unique index sees the demotion
                # before we try to INSERT the new active row.
                s.flush()
            pem, jwk = _generate_rsa_keypair()
            row = orm.OAuthSigningKey(
                kid=jwk["kid"],
                alg="RS256",
                public_jwk=jwk,
                private_pem=pem,
                status="active",
            )
            s.add(row)
            s.commit()
            new = _row_to_signing_key(row)
        # Invalidate the cache so the next sign() picks up the new key.
        self._cached = None
        return new

    def prune_retiring(self, *, max_token_ttl_seconds: int) -> int:
        """Demote ``retiring`` keys whose grace period elapsed to ``revoked``.

        Grace period is ``2 * max_token_ttl_seconds`` so even the longest
        in-flight token had time to expire before its verifier disappears.
        Returns the number of keys revoked. Idempotent.
        """
        from datetime import timedelta

        from sqlalchemy import select

        from authzkit.storage import orm

        cutoff = datetime.now(UTC) - timedelta(seconds=2 * max_token_ttl_seconds)
        revoked = 0
        with self.store.session() as s:
            rows = s.scalars(
                select(orm.OAuthSigningKey).where(
                    orm.OAuthSigningKey.status == "retiring"
                )
            ).all()
            for row in rows:
                rotated = row.rotated_at
                if rotated is None:
                    continue
                if rotated.tzinfo is None:
                    rotated = rotated.replace(tzinfo=UTC)
                if rotated <= cutoff:
                    row.status = "revoked"
                    revoked += 1
            s.commit()
        return revoked

    # ----- signing / verifying ---------------------------------------------

    def sign(self, claims: dict[str, Any]) -> str:
        """Sign a JWT claim set with the active key.

        Always emits RS256 with the active ``kid`` in the header. Caller is
        responsible for setting ``iss``, ``aud``, ``exp``, ``iat``, ``nbf``,
        ``jti``, etc — this method does not add or validate claims.
        """
        import jwt

        key = self.active_signing_key()
        return jwt.encode(
            claims,
            key.private_pem,
            algorithm=key.alg,
            headers={"kid": key.kid, "typ": "JWT"},
        )

    def list_keys(self) -> list[SigningKey]:
        """Admin view of all keys in the DB (env keys are not enumerated here)."""
        from sqlalchemy import select

        from authzkit.storage import orm

        with self.store.session() as s:
            rows = s.scalars(select(orm.OAuthSigningKey)).all()
            return [_row_to_signing_key(r) for r in rows]


def _row_to_signing_key(row: Any) -> SigningKey:
    return SigningKey(
        kid=row.kid,
        alg=row.alg,
        status=row.status,
        private_pem=row.private_pem,
        public_jwk=dict(row.public_jwk),
        created_at=row.created_at,
    )
