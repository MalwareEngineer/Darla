"""Application configuration via pydantic-settings."""

import ipaddress
from functools import lru_cache

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="PK_",
        case_sensitive=False,
        extra="ignore",
    )

    # Application
    app_name: str = "Darla"
    debug: bool = False
    log_level: str = "INFO"

    # Database (async for FastAPI)
    database_url: str = (
        "postgresql+asyncpg://localhost:5432/darla"
    )
    # Sync database URL for Celery workers
    sync_database_url: str = (
        "postgresql+psycopg2://localhost:5432/darla"
    )
    database_pool_size: int = 20
    database_max_overflow: int = 10

    # Redis
    redis_url: str = "redis://localhost:6379/0"
    redis_cache_ttl: int = 300

    # Celery
    celery_broker_url: str = "amqp://localhost:5672//"
    celery_result_backend: str = "redis://localhost:6379/1"

    # Analysis
    kit_download_dir: str = "./downloads"
    kit_extract_dir: str = "./extracted"
    max_kit_size_mb: int = 50
    download_timeout: int = 30
    # Non-public networks outbound fetches may still reach (see
    # darla.utils.egress).  Empty = only globally routable addresses.  For
    # lab setups hosting test kits on a LAN, e.g. ["192.168.50.0/24"].
    # Env format is JSON: PK_EGRESS_ALLOW_CIDRS=["192.168.50.0/24"]
    egress_allow_cidrs: list[str] = []
    tlsh_min_size: int = 50
    yara_rules_dir: str = "./rules"

    # Browser-based downloading (Camoufox stealth browser fallback)
    browser_download_enabled: bool = False
    browser_download_timeout: int = 60
    # SOCKS5 egress proxy for Camoufox (darla.egress_proxy), e.g.
    # "socks5://egress-proxy:1080".  Empty = the browser connects directly
    # and is NOT covered by the SSRF guard.
    browser_egress_proxy: str = ""
    browser_turnstile_timeout: int = 30  # seconds before retrying Turnstile with fresh context
    browser_render_on_thin_results: bool = True
    browser_dedup_tlsh_threshold: int = 30
    # Total browser_render children allowed per investigation.  Caps the
    # blast radius of relay-pool enumeration: a single adversarial AITM
    # kit with rotating relays would otherwise dispatch up to 50 renders.
    # 10 catches realistic pool sizes; bump if a kit consistently shows
    # legitimate variations beyond the cap.
    browser_render_max_variations: int = 10
    # Consecutive TLSH-duplicate renders before stopping the pool-enum
    # loop.  At 1 we stop on the first duplicate: a near-duplicate render
    # means the pool isn't yielding new content, and per-render token
    # variation within one tree isn't worth a 60-150 s browser slot —
    # kit variation is compared across submissions (PhishDiff) instead.
    # (2 cost an extra confirming render per lure; 3 wasted ~33% more.)
    browser_render_pool_stop: int = 1
    # Per-investigation in-flight browser-render budget.  Before
    # dispatching another browser_download_kit (e.g. pool enumeration),
    # we count DOWNLOADING children for the same investigation; if this
    # cap is hit we suppress the new dispatch and let in-flight work
    # finish first.  Smooths queue spikes from adversarial kits without
    # starving other investigations on a shared browser worker.
    browser_render_max_inflight_per_investigation: int = 2

    # Polymorphism detection
    browser_polymorphism_min_variants: int = 2      # min unique siblings on same domain
    browser_polymorphism_tlsh_max_distance: int = 200  # above this = unrelated, not polymorphic

    # External JS fetching (follow <script src="..."> in rendered pages)
    external_js_fetch_enabled: bool = True
    external_js_fetch_timeout: int = 15        # per-request timeout (seconds)
    external_js_fetch_max_depth: int = 2       # recursive JS→JS following depth
    external_js_fetch_max_files: int = 10      # max files to fetch per kit
    external_js_fetch_max_size_kb: int = 512   # max individual JS file size

    # Passive artifact rendering (EML / SVG / PDF / DOCX → _screenshots)
    artifact_render_enabled: bool = True

    # Active SVG execution — detonates SVG attachments with JS enabled and
    # captures all outbound network requests.  Goal: one-shot capture of the
    # full attacker infrastructure chain (SVG → remote loader → landing
    # page) without a second manual kit resubmission.  Terminal URLs feed
    # the chain crawler so child kits spawn automatically.
    svg_active_exec_enabled: bool = True
    svg_active_exec_timeout: int = 30        # per-SVG wall-clock budget (sec)
    svg_active_exec_max_requests: int = 200  # cap per SVG
    svg_active_exec_max_per_kit: int = 3     # at most N SVGs per kit get detonated

    # Chain crawling
    chain_max_depth: int = 5
    chain_max_children_per_kit: int = 10
    chain_link_score_threshold: float = 0.5
    chain_enabled: bool = True

    # Campaign auto-creation
    campaign_tlsh_threshold: int = 30

    # CORS
    cors_origins: list[str] = ["http://localhost:5173"]

    # ─── Auth & Identity (RFC 0001) ──────────────────────────────────────
    #
    # Defaults are tuned for community / local-evaluation use:
    # ``auth_enabled=False`` lets ``docker compose up`` work without an
    # IdP.  Production deployments set ``auth_enabled=True`` (hardcoded
    # in the deployment-repo Terraform — see RFC §16 guardrail #2).
    #
    # When ``auth_enabled=False``, six startup guardrails (RFC §16)
    # refuse to run anywhere that looks like production: requires the
    # explicit ack token, refuses non-localhost binds, refuses to start
    # if AWS IMDS is reachable, refuses to start outside debug mode.
    # See ``darla.auth.guardrails``.

    # Master switch.  False = community/local mode (no auth, with
    # safety guardrails).  True = OIDC enforcement on protected routes.
    auth_enabled: bool = False

    # Required exact-string acknowledgement when ``auth_enabled=False``.
    # Verbose enough that no one sets this by accident or copies it
    # without noticing.  Any other value (including the default empty
    # string) causes the guardrails to refuse startup.
    i_understand_auth_is_off: str = ""

    # Host address the API is published on.  Under Docker Compose this
    # is the host side of the ``api`` port mapping
    # (``${PK_BIND_ADDRESS}:8000:8000``) and compose passes the same
    # interpolated value into the container, so the guardrail checks
    # exactly what Docker bound.  Guardrails refuse anything but
    # ``127.0.0.1`` / ``localhost`` / ``::1`` when ``auth_enabled=False``
    # — disabled-mode deployments must not be network-reachable.
    bind_address: str = "127.0.0.1"

    # OIDC issuer URL — only consulted when auth is enabled.  Used both
    # for the ``iss`` claim check on incoming JWTs and for OIDC discovery
    # (``<issuer>/.well-known/openid-configuration`` → ``jwks_uri``).
    # Examples:
    #   Entra:    https://login.microsoftonline.com/<tenant-id>/v2.0
    #   Okta:     https://<your-org>.okta.com/oauth2/default
    #   Keycloak: https://<host>/realms/<realm>
    oidc_issuer: str = ""

    # Expected ``aud`` claim — usually the API's client/application ID
    # in your IdP.  For Entra, this is the "Darla API" registration's
    # Application (client) ID.
    oidc_audience: str = ""

    # Optional override for the JWKS URL.  Leave blank to auto-discover
    # via ``<issuer>/.well-known/openid-configuration``.  Set explicitly
    # only if the IdP doesn't expose discovery (rare) or you want to
    # pin the JWKS endpoint.
    oidc_jwks_url: str = ""

    # JWKS cache TTL in seconds.  Defaults to 1 hour — IdP key rotation
    # cadences range from days (Auth0) to ~24h (Entra), so 1h gives us
    # a worst-case 1h window of accepting tokens signed by a key the
    # IdP just rotated out.  ``kid`` mismatch triggers a forced refresh
    # regardless of TTL, so legitimate rotations resolve within one
    # rejected request.
    oidc_jwks_cache_ttl: int = 3600

    # JWT signature algorithms the API accepts.  The allowlist is
    # server-side on purpose: taking the algorithm from the token's own
    # header is the classic alg-confusion hole (``HS256`` signed with
    # the public key, or ``none``).  Guardrails refuse any symmetric or
    # ``none`` entry at startup.  Entra/Okta/Auth0 sign RS256; add e.g.
    # ``PS256`` / ``ES256`` for a Keycloak realm configured that way.
    # Env format is JSON: ``PK_OIDC_ALLOWED_ALGORITHMS=["RS256","ES256"]``.
    oidc_allowed_algorithms: list[str] = ["RS256"]

    # JSON path inside the JWT to find the user's stable subject.
    # OIDC standard is ``sub``.  Entra deployments override to ``oid``
    # because Entra's ``sub`` is per-app pairwise (would change if we
    # spin up a second app registration).
    oidc_subject_claim: str = "sub"

    # JSON path inside the JWT to find the role(s) array.  Supports
    # dotted paths for nested objects (e.g. Keycloak's
    # ``realm_access.roles``).  Per-IdP defaults:
    #   Entra:    "roles"     (custom claim from app role assignment)
    #   Okta:     "groups"    (with a "groups" claim added to the auth server)
    #   Keycloak: "realm_access.roles"
    #   Auth0:    "https://your-app.example.com/roles"  (custom namespace)
    oidc_role_claim: str = "roles"

    # The exact string in the role-claim array that grants viewer /
    # analyst access.  These match the App Role values configured in
    # the IdP.  Configurable so deployments using existing groups
    # (e.g. ``sg-darla-analysts``) can map without renaming.
    oidc_viewer_role_value: str = "Darla.Viewer"
    oidc_analyst_role_value: str = "Darla.Analyst"

    @field_validator("egress_allow_cidrs")
    @classmethod
    def _valid_cidrs(cls, value: list[str]) -> list[str]:
        # Fail at startup, not on the first fetch that consults the list.
        for cidr in value:
            ipaddress.ip_network(cidr, strict=False)
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()
