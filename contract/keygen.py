"""Create the fixture's RSA signing key once (``.secrets/signing-key.pem``).

The key stays fixed for as long as ``contract/.secrets`` is kept, so tokens
and delegation grants keep the same ``kid`` across restarts. Drop your own
PKCS#8 PEM there to pin a specific key. Never commit it: ``.secrets`` is
gitignored and test-only.
"""

from __future__ import annotations

import sys
from pathlib import Path

from authzkit.security.signing_keys import _generate_rsa_keypair


def main() -> None:
    out = Path(sys.argv[1] if len(sys.argv) > 1 else Path(__file__).parent / ".secrets")
    path = out / "signing-key.pem"
    if path.exists():
        print(f"signing key present: {path}")
        return
    out.mkdir(parents=True, exist_ok=True)
    pem, _ = _generate_rsa_keypair()  # same RSA-2048 PKCS#8 key the service generates
    path.write_bytes(pem.encode("ascii"))
    print(f"signing key created: {path}")


if __name__ == "__main__":
    main()
