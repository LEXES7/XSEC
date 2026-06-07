"""Small shared networking helpers."""

from __future__ import annotations

import ssl


def ssl_context() -> ssl.SSLContext:
    """TLS context that verifies certs, using certifi's bundle if available.

    Some Python installs (notably python.org builds on macOS) ship without a
    working system cert store; certifi gives us a reliable one. We never skip
    verification.
    """
    try:
        import certifi
        return ssl.create_default_context(cafile=certifi.where())
    except ImportError:
        return ssl.create_default_context()
