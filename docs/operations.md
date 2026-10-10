# Operations and API

[← Project overview](../README.md) · [Production deployment](../deploy/production/README.md)

This guide covers the runtime and API details for an OSA instance. For first-time
startup, use the [quick start](../README.md#quick-start). For external HTTPS,
credentials and existing database migration, follow the production guide.

[API](#api) · [Accounts](#accounts) · [Metrics and backups](#prometheus-and-logs) · [Gate policy](#gate-policy) · [Nexus](#nexus-gateway) · [Configuration](#configuration)

## API

The scan endpoints below require a session cookie or `X-Api-Key` header.
Administrators can create a key under **Manage Users → API Keys**, opened from
the account menu. Set `OSA_URL` to your instance URL and `OSA_API_KEY` to your
key before running the examples.

```bash
# Library
curl -X POST "$OSA_URL/api/libscan" \
  -H "X-Api-Key: $OSA_API_KEY" -H 'Content-Type: application/json' \
  -d '{"name":"lodash","ecosystem":"npm","version":"4.17.20"}'

# Docker image
curl -X POST "$OSA_URL/api/trivy/scan" \
  -H "X-Api-Key: $OSA_API_KEY" -H 'Content-Type: application/json' \
  -d '{"image":"nginx","tag":"latest"}'

# Public GitHub repository
curl -X POST "$OSA_URL/api/ghscan" \
  -H "X-Api-Key: $OSA_API_KEY" -H 'Content-Type: application/json' \
  -d '{"url":"https://github.com/ShinigamiKiko/osa-hunter"}'
```

Full endpoint list: `libscan` · `depscan` · `composer` · `osscan` · `trivy/scan` · `ghscan` · `scans/history` · `export/pdf`

Image scans accept a repository name and a separate tag. Unqualified names such
as `nginx` use Docker Hub. `TRIVY_ALLOWED_REGISTRIES` is a comma-separated list of
exact registry hosts, including ports where used. Defaults allow Docker Hub,
GHCR, Quay, Kubernetes, Microsoft, Google and public ECR registries. Add private
registries explicitly; an empty list rejects all image scans. The check runs
before cache access and Trivy execution, including scans requested by PDF export.
It restricts the registry named in a submitted image reference. Registry redirects,
authentication endpoints and external layer URLs still require network-level
egress controls when strict outbound isolation is needed.

PDF rendering keeps JavaScript and external resource loading disabled. Chromium
uses its sandbox by default in direct backend launches. Compose defaults
`PUPPETEER_NO_SANDBOX=true` for hosts whose container policy prevents sandbox
namespace creation; set it to `false` when the host supports sandboxing. There is
no automatic fallback after a sandbox failure. The image includes
`chromium-sandbox` and runs as a non-root user.

### Accounts

Any signed-in user changes their own password from the account menu in the top
right: `POST /api/auth/password` with `currentPassword` and `newPassword`. The
current password is required, the new one must be at least 8 characters, and the
session id is rotated on success. Only a wrong current password counts against
the rate limit, so a mistyped form cannot lock anyone out.

Sign-in attempts are limited to ten per minute per IP and per trimmed,
case-sensitive username. Unknown users still run a cost-12 bcrypt comparison
and return the same invalid-credentials response as wrong passwords.

An admin resets somebody else's password in **Manage Users**
(`PATCH /api/auth/users/:id/password`); that path does not ask for the old one.

Password changes revoke other browser sessions; an admin reset revokes all of
that account's browser sessions. Account deletion and role changes are checked
on every authenticated request, including `/api/auth/me`. API keys remain
separate credentials. Only administrators can save the gateway policy.

The session-version migration requires existing users to sign in again once.
The enrichment migration discards old library, dependency, OS and gate cache
entries because their verdicts may be incomplete; these scans will run again
on demand.

The Compose frontend and backend ports are published on localhost. Forwarded client
addresses are trusted only from the `frontend` container. For another reverse
proxy, set `TRUSTED_PROXIES` to its addresses/CIDRs or `TRUSTED_PROXY_HOSTS` to
its DNS names. Direct deployments ignore forwarded headers by default.

### Prometheus and logs

Metrics are published on a separate port bound to localhost only, not on the
public API port:

```bash
curl http://localhost:9100/metrics
```

The backend writes one JSON object per line to stdout. Each HTTP request includes
`timestamp`, `requestId`, `method`, `path`, `statusCode` and `durationMs` fields.
Sensitive authorization headers and cookies are never included in request logs.

`GET /api/ready` checks PostgreSQL connectivity and is used by the backend
container healthcheck. Long-running Trivy and Grype operations are limited by
`TRIVY_CONCURRENCY`/`GRYPE_CONCURRENCY` and their queue-size settings. External
HTTP calls use `HTTP_TIMEOUT_MS` and `HTTP_CONCURRENCY` as shared defaults.

`TRIVY_QUEUE_SIZE` and `GRYPE_QUEUE_SIZE` limit waiting scan requests. A full
queue returns HTTP `503`; the per-client rate limits return HTTP `429`. The
default limits are 5 Trivy requests/minute, 20 scan requests/minute, 120 API
requests/minute and 120 gateway requests/minute.

PDF exports use `PDF_CONCURRENCY` (default 1) and `PDF_QUEUE_SIZE` (default 4).
A full PDF queue returns HTTP `503` with a `Retry-After` header. Dependency
graphs above 500 packages return HTTP `413` instead of a partial result.
A failed Semgrep run or malformed output returns HTTP `502`. Files Semgrep
could not analyze (parse errors, per-file timeouts) keep the other findings but
mark the result `complete: false` with `errors` and `errorSamples`; incomplete
results of any scan are never cached.
Older SAST results without a completion marker require a rescan.

Scan and gate results are stored in PostgreSQL. A cache hit returns immediately
with `_cached: true`; a cache miss runs the scan and stores its result. The
`osa_cache_operations_total` metric tracks hits and misses by cache type.

For a Compose backup, dump PostgreSQL and archive the named volumes before
upgrades. The Nexus archive is only needed when you run Nexus; adjust the volume
name if you use a different Compose project name. For example:

```bash
docker compose exec -T postgres sh -c \
  'pg_dump -U "$POSTGRES_USER" "$POSTGRES_DB"' > osa.sql
docker run --rm -v osa-hunter_nexus-data:/data -v "$PWD":/backup alpine \
  tar czf /backup/nexus-data.tgz -C /data .
```

## Package Proxy

OSA accepts package-manager metadata and archive requests, checks the package
name and version against OSV and the active database policy, and streams allowed bytes from
the configured upstream. It does not install or execute packages. The open
gateway is read-only and only accepts known package paths and metadata paths.

The policy is evaluated after the package name and version are resolved.

## Gate Policy

The enforced policy lives in the database. On first boot `policy.yaml` is
imported, so an existing file-based setup keeps working and its rules appear in
the UI unchanged.

Manage it under **Rules** in the sidebar. Two kinds of rule share one list:

- **by name** — the package name is matched before anything is scanned, so it
  works in every ecosystem and never depends on a feed being reachable
  (`curl`, `npm/left-pad@1.3.0`, `crossenv*`);
- **by scan result** — conditions over the findings: severity counts, CISA KEV,
  EPSS, PoC, CVE ids.

Saving replaces the policy and takes effect immediately. There is no revision
history: keep the audited copy in git by pasting **Export YAML** into
`policy.yaml`. Every save bumps an internal counter that is part of the
verdict-cache key, so decisions cached under the previous policy are never
reused.

| Endpoint | Purpose |
|---|---|
| `GET /api/policy` | the policy the gate enforces |
| `GET /api/policy/yaml` | export it as `policy.yaml` |
| `PUT /api/policy` | replace it (`body` or `yaml`) |
| `POST /api/policy/normalize` | validate without storing |
| `GET /api/policy/facts` | the facts rules can match on |

These policy endpoints require authentication; saving requires an administrator.
Package-manager routes under `/api/gate` are open. A policy is data, never code — rules are `{fact: expression}` pairs
interpreted by `lib/gate/policy.js`, and nothing in a policy is evaluated as JS.

**Blocked vs. undecidable.** A package the policy rejects returns `403 Blocked by
OSA gate (<rule>)`. When `defaults.on_gate_error` is `deny` and the vulnerability
data itself is unreachable, the package is still not served, but it was never
judged — that answer is `503 OSA gate: vulnerability data unavailable, retry`
with a `Retry-After` header, so clients retry instead of reporting the package as
forbidden by policy. Fail-closed verdicts are never cached.


## Nexus Gateway

OSA can run in front of Nexus and gate artifact requests before forwarding them:

```text
client -> OSA /api/gate/<repository>/... -> Nexus /repository/<repository>/... -> upstream registry
```

For local development, the commands below assume your mappings are configured.
Use your HTTPS instance URL in production.

Configure `NEXUS_UPSTREAM` and map repository names with
`OSA_NEXUS_REPOSITORIES`. Supported ecosystems are npm (JS/TS), PyPI
(Python), Packagist (PHP), Go, Maven (Java/Kotlin), NuGet (.NET), crates.io
(Rust), RubyGems (Ruby), Debian/Ubuntu, Alpine and RPM-based distributions.
Clients use `/api/gate/<repository>/...`:

```bash
npm pack is-odd@3.0.1 --ignore-scripts --registry=http://localhost:3000/api/gate/npm-proxy
export GOPROXY=http://localhost:3000/api/gate/go-proxy
python -m pip download --no-deps --trusted-host localhost \
  --index-url http://localhost:3000/api/gate/pypi-proxy/simple idna==3.10
export CARGO_REGISTRIES_CRATES_IO_INDEX=sparse+http://localhost:3000/api/gate/cargo-proxy/
```

Artifact requests are gated lazily; metadata requests are forwarded without
scanning every historical version. Unknown artifact paths are blocked while
`OSA_NEXUS_STRICT=true`. Cargo uses `index.crates.io` for metadata and
`static.crates.io` for archive downloads; configure `downloadUpstream` for that
repository when using direct mirrors.

### Nexus on a separate host

Nexus is optional and off by default. To run it on its own machine, use
`deploy/nexus/` there:

```bash
docker compose -f deploy/nexus/docker-compose.yml up -d
docker exec nexus cat /nexus-data/admin.password     # first boot only
./deploy/nexus/bootstrap.sh http://nexus.example.com:8081 '<password>'
```

Then point OSA at it in `.env` and restart the backend:

```env
NEXUS_UPSTREAM=http://nexus.example.com:8081
NEXUS_AUTH=Basic <base64 of admin:password>
```

Only repositories without their own `upstream` go through Nexus; anything with
`"direct": true` in `OSA_NEXUS_REPOSITORIES` fetches from the internet itself and
ignores these settings. To keep a Nexus next to OSA instead, start it with
`docker compose --profile nexus up -d`.

## Configuration

Generate credentials with `node scripts/init-env.cjs` for production, or add
`--development` for a local HTTP instance. The helper creates `.env` with unique
credentials and a persistent session secret; it does not overwrite an existing
file. Do not commit `.env`.

See [`.env.example`](../.env.example) for settings and defaults. Optional
`NVD_API_KEY` is available from [NVD](https://nvd.nist.gov/developers/request-an-api-key).
`SCAN_CACHE_TTL_HOURS` controls scan result lifetime; `CVE_CACHE_TTL_HOURS` controls
enrichment data refresh. Gateway enrichment sources are selected with
`OSA_KEV_ENABLED`, `OSA_EPSS_ENABLED`, `OSA_POC_ENABLED` and `OSA_TOXIC_ENABLED`.

Production requires `HTTPS=true`, secure cookies and strong credentials. Use the
[production Compose override](../docker-compose.production.yml) with an external
HTTPS nginx/Ingress; the [deployment guide](../deploy/production/README.md) explains
the required headers, network boundaries and credential rotation.

## Toxic repository matching

Toxic checks compare package identities and source repositories against a
curated feed of repositories known to contain malicious or harmful code. When
enabled for the gate, this signal can be used in rules through `toxic.found`.

Matches use an explicit package URL/PURL or the package's source repository from
registry metadata, including its host and owner. A repository basename or an
unscoped package name alone is insufficient. Repository lookup supports npm,
PyPI, Packagist, crates.io, RubyGems and GitHub-hosted Go modules; other ecosystems
require an explicit package identity in the feed. GitHub scans compare the full
repository identity. Metadata lookups are cached; failures in a toxic gate rule
follow `on_gate_error`. Feed entries retain the categories assigned by its authors.

| Category | Description |
|---|---|
| 💀 DDoS Tool | Packages designed to flood networks or amplify attacks |
| 🦠 Malware | Trojans, ransomware, or data-stealing payloads |
| ⚡ Hostile Actions | Code that destroys data or sabotages systems |
| 🚫 IP Blocking | Geofencing or censorship embedded in a library |
| 📢 Political Slogan | Activist payloads that hijack package behavior |

## Security

- Passwords hashed with **bcrypt** (12 rounds)
- API keys stored as **SHA-256 hashes** only
- Login rate-limited — 10 attempts/minute per IP
- `HttpOnly` + `SameSite=lax` cookies
- HTTPS-only `__Host-osa.sid` cookies when `SESSION_COOKIE_SECURE=true`
- `X-Frame-Options` · `CSP` · `Referrer-Policy` headers
