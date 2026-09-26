"""Suite-wide test environment.

Pins the three no-auth startup-guardrail settings (RFC §16) so the suite
doesn't depend on a developer's local ``.env``: environment variables
take precedence over ``.env`` in pydantic-settings, and this module is
imported before any test module, i.e. before ``get_settings()`` caches.

Without this, anything that builds the app at import time
(``tests/test_auth/test_route_coverage.py`` imports ``darla.main``)
exits through the ack-token guardrail on a machine with no ``.env`` —
which is how CI first failed.  Tests that exercise the guardrails build
their own ``Settings`` objects and are unaffected.
"""

from __future__ import annotations

import os

os.environ["PK_I_UNDERSTAND_AUTH_IS_OFF"] = "yes-only-for-local-eval"
os.environ["PK_DEBUG"] = "true"
os.environ["PK_BIND_ADDRESS"] = "127.0.0.1"
