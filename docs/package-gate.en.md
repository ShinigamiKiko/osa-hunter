# Package Security Gate

OSA Hunter is an open package proxy that evaluates package risk before serving
an archive to a client.

## Request flow

```text
package manager -> OSA gate -> OSV + policy -> upstream -> package manager
```

1. The client requests metadata or an archive through `/api/gate/<repository>/...`.
2. OSA resolves the ecosystem, package name, and version from the path.
3. Archive requests are evaluated with OSV, enrichment data, and `policy.yaml`.
4. A `deny` decision returns HTTP `403`.
5. An allowed archive is fetched from upstream and streamed to the client.

OSA does not install, extract, or execute packages. OSA does not store archive
files on disk; Nexus may provide its own cache.

## Policy decisions

- `allow` - the package may be fetched.
- `warn` - the package may be fetched; the API decision includes a warning.
- `deny` - the package is blocked with HTTP `403`.

Gate errors fail closed: an unavailable security check never becomes an allow.
An unavailable upstream is returned as `502`.

Example `policy.yaml`:

```yaml
version: 1

defaults:
  decision: allow
  on_gate_error: deny

rules:
  - id: actively-exploited
    action: deny
    when:
      kev: yes
    detail: package is listed in CISA KEV

  - id: critical
    action: deny
    when:
      counts.CRITICAL: ">= 1"

  - id: high-epss
    action: deny
    when:
      all:
        - counts.HIGH: ">= 1"
        - epssMax: ">= 0.5"

exceptions:
  allow: []
  deny: []
```

Rules support `all`, `any`, numeric comparisons, boolean values, and glob
patterns such as `CVE-2026-*`.

Available policy facts include:

- `counts.CRITICAL`, `counts.HIGH`, `counts.MEDIUM`, `counts.LOW`;
- `topSeverity`;
- `kev`;
- `epssMax`;
- `pocCount`;
- `cves`, `cveCount`, `ids`;
- `toxic.found`.

The shipped root `policy.yaml` is the source of truth for the active policy.

## Supported ecosystems

- npm: `.tgz`
- PyPI: `.whl`, `.tar.gz`, `.zip`
- Go modules: `.zip`, `.mod`, `.info`
- Composer/Packagist: `.zip`
- Maven: `.jar`, `.pom`, `.module`
- NuGet: `.nupkg`
- Cargo/crates.io: `.crate`
- RubyGems: `.gem`
- Alpine: `.apk`
- Debian/Ubuntu: `.deb`
- Rocky, AlmaLinux, CentOS, RHEL, openSUSE/SUSE: `.rpm`

Metadata is handled separately and is limited to known package-manager paths.
Arbitrary `.sh`, `.js`, `.py`, `.php`, and unknown files are not proxied.

## Configuration

Repositories are configured with `OSA_NEXUS_REPOSITORIES`. A value can be a
Nexus repository name or an object containing `ecosystem`, `upstream`,
`direct`, and, for Cargo, `downloadUpstream`.

Example:

```env
OSA_NEXUS_REPOSITORIES={"ubuntu-2404":{"ecosystem":"Ubuntu:24.04","upstream":"https://archive.ubuntu.com/ubuntu","direct":true},"centos-stream9-baseos":{"ecosystem":"CentOS:9","upstream":"https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os","direct":true},"rhel9-baseos":{"ecosystem":"Red Hat:9"}}
```

RHEL normally requires a subscription mirror or an internal Nexus repository.

## Verification

Run unit and connector tests:

```bash
cd backend
npm test
```

Run live checks through Node.js `fetch`, without `curl` and without installing
packages:

```bash
OSA_LIVE_CONNECTORS=true node --test test/connectors.integration.test.js
```

The live suite checks metadata and archive paths for every connector, Cargo
download URL rewriting, policy `403`, and controlled `502` upstream failures.
