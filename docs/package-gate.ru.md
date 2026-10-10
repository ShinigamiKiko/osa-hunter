# Package Security Gate

OSA Hunter - открытый package proxy с проверкой безопасности перед выдачей
архива клиенту.

## Как работает запрос

```text
package manager -> OSA gate -> OSV + policy -> upstream -> package manager
```

1. Клиент запрашивает metadata или архив через `/api/gate/<repository>/...`.
2. OSA определяет ecosystem, имя и версию из пути.
3. Для архива выполняется проверка через OSV, enrichment и активную политику.
4. При `deny` OSA возвращает `403`.
5. При разрешении OSA получает архив у upstream и передает его клиенту потоком.

OSA не устанавливает, не распаковывает и не выполняет пакет. Архив не хранится
на диске OSA; собственный cache может использовать Nexus.

## Решения policy

- `allow` - пакет можно получить.
- `warn` - пакет можно получить; решение содержит предупреждение для API.
- `deny` - пакет блокируется с HTTP `403`.

При `defaults.on_gate_error: deny` недоступная обязательная проверка возвращает
HTTP `503` с `Retry-After`, чтобы клиент мог повторить запрос. Это отличается
от блокировки по политике (`403`); результат недоступной проверки не кешируется
как вердикт. Ошибка upstream возвращается клиенту как `502`.

Пример `policy.yaml`:

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

Поддерживаются условия `all`, `any`, сравнения `>`, `>=`, `<`, `<=`, `==`,
`!=`, boolean-значения и glob-шаблоны вроде `CVE-2026-*`.

Факты, доступные policy:

- `counts.CRITICAL`, `counts.HIGH`, `counts.MEDIUM`, `counts.LOW`;
- `topSeverity`;
- `kev`;
- `epssMax`;
- `pocCount`;
- `cves`, `cveCount`, `ids`;
- `toxic.found`.

Корневой `policy.yaml` импортируется при первом запуске. Активная политика
хранится в PostgreSQL и редактируется в разделе **Rules**. Изменение исходного
файла не заменяет политику в существующей базе. Сохраняйте проверенную копию
через **Export YAML** в Git; сохранение политики отменяет ранее кешированные
вердикты.

API политики описан в [Operations and API](operations.md#gate-policy), настройка
HTTPS для клиентов — в [инструкции по production](../deploy/production/README.md).

## Поддерживаемые ecosystem

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

Metadata разрешается отдельно и только по известным путям package manager.
Произвольные `.sh`, `.js`, `.py`, `.php` и другие неизвестные файлы не
проксируются.

## Настройка

Репозитории задаются в `OSA_NEXUS_REPOSITORIES`. Значение может быть строкой
для Nexus repository или объектом с `ecosystem`, `upstream`, `direct` и, для
Cargo, `downloadUpstream`.

Пример:

```env
OSA_NEXUS_REPOSITORIES={"ubuntu-2404":{"ecosystem":"Ubuntu:24.04","upstream":"https://archive.ubuntu.com/ubuntu","direct":true},"centos-stream9-baseos":{"ecosystem":"CentOS:9","upstream":"https://mirror.stream.centos.org/9-stream/BaseOS/x86_64/os","direct":true},"rhel9-baseos":{"ecosystem":"Red Hat:9"}}
```

RHEL обычно требует subscription mirror или внутренний Nexus repository.
