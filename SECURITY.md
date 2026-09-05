# Security Model & Considerations

QUARR runs real offensive/defensive security tooling. This document describes
its security guarantees, hardening measures, and known limitations so operators
can deploy it responsibly in professional engagements.

> **Authorization first.** Only run QUARR against systems you are explicitly
> authorized to assess. Define scope precisely — the policy engine enforces it,
> but you are responsible for the authorization behind it.

## Command execution safety

- **No shell by default.** Tools execute via an argument vector with
  `shell=False` (`quarr/tools/executor.py`). Arguments are validated against an
  allowlist (`quarr/core/validators/command.py`) that blocks shell
  metacharacters (`; | $ \` < >` and newlines).
- **URL arguments are supported.** Query/fragment characters (`? & # ~ [ ]`) are
  permitted because they are inert under `shell=False`; this is required for
  parameterized targets (e.g. `http://host/page?id=1&x=2`) used by SQLi/nuclei
  and other web tools.
- **Tool inputs are validated.** Targets, domains, IPs, package names, hashes,
  severities, and tool modes are validated/quoted before command construction.
  Discovered filesystem paths (e.g. MySQL/Apache config paths) are `shlex`-quoted.
- **Path traversal is blocked.** Engagement IDs and evidence filenames are
  validated and contained within the engagements directory
  (`quarr/core/persistence.py` via `quarr/core/validators/path.py`). Session
  bundle import rejects zip-slip.

## Secrets handling

- **Redaction.** `quarr/core/secrets.redact()` scrubs free-text output sent to
  the API, WebSocket stream, notifications, and reports. It covers
  password/secret/token/credential/authorization key-values, Bearer tokens, JWTs,
  AWS/OpenAI/GitHub/Slack tokens, private-key blocks, and basic-auth URLs.
  WebSocket payloads are redacted recursively (nested structures included).
- **Structured logs** use a key-based redaction processor
  (`quarr/core/logging.py`).
- Redaction is best-effort defense-in-depth, not a guarantee that no secret can
  ever appear in output. Treat reports/logs as sensitive.

## API / multi-user deployment

- **Authentication.** JWT (HS256) with access + refresh tokens. The server
  **refuses to start** if `jwt_secret` is unset or left at the shipped default
  (`assert_secure_config()` at startup). Always set `QUARR_JWT_SECRET` to a
  strong random value.
- **Authorization.** Role-based (`viewer` < `operator` < `admin`). Tool risk
  levels map to a minimum role; CRITICAL tools require `admin`. Refresh
  re-resolves the user's *current* stored role (a downgraded/removed account
  cannot retain elevated access).
- **WebSockets.** Both `/ws` and `/ws/live` require a valid access token.
- **CORS.** Configure `QUARR_CORS_ORIGINS` to an explicit allowlist in
  production. Do not ship the wildcard default to the internet.

### Known limitations (professional deployments)

- **No per-engagement ownership model.** Authorization is role-only: any
  authenticated user of a sufficient role can access any engagement. For
  multi-tenant use, deploy one instance per client or add an ownership layer.
- **Evidence chain-of-custody** hashes are stored alongside the evidence. This
  detects accidental corruption; it is not a tamper-proof anchor (no external
  signature/HMAC). For legal-grade custody, export bundles to signed/append-only
  storage.
- **Threat-intel** enrichment (VirusTotal, AbuseIPDB, Shodan) requires
  third-party API keys. Without them the tools return a clear error and the
  aggregator falls back to the keyless NVD CVE source.

## Reporting a vulnerability

If you discover a security issue in QUARR itself, do not open a public issue.
Contact the maintainers privately with details and reproduction steps.
