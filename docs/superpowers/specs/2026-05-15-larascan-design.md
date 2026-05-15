# Larascan — design spec

**Date:** 2026-05-15
**Status:** Design approved, pending implementation plan

A Laravel package that scans an application for security issues. Pure security focus (no performance, no reliability). Hybrid implementation: own Laravel-specific analyzers plus wrappers around Semgrep, PHPStan, composer audit, and npm audit. Static-only — no runtime probing. CLI output for v1.

## Package identity & dependencies

- **Name:** `baspa/larascan`
- **Namespace:** `Baspa\Larascan\`
- **Service provider:** `LarascanServiceProvider` via `spatie/laravel-package-tools`
- **PHP:** `^8.2`
- **Laravel:** `^10.0 || ^11.0 || ^12.0 || ^13.0`
- **Runtime deps:** `illuminate/contracts`, `spatie/laravel-package-tools`, `nikic/php-parser`, `symfony/process`, `symfony/yaml`
- **Dev deps:** `larastan/larastan ^3`, `phpstan/phpstan ^2`, `phpstan/extension-installer`, `pestphp/pest ^4`, `pestphp/pest-plugin-laravel`, `orchestra/testbench`, `laravel/pint`
- **External tools (binary detection at install time):** `semgrep`, `npm`. `composer audit` is native.
- **Strictness:** `declare(strict_types=1)` everywhere. PHPStan **level 8** in CI for our own code.

## Directory layout

```
larascan/
├── config/
│   └── larascan.php
├── resources/
│   └── stubs/
│       ├── workflow.yml.stub
│       ├── semgrep.yml.stub
│       └── phpstan.neon.stub
├── src/
│   ├── LarascanServiceProvider.php
│   ├── Larascan.php
│   ├── Facades/Larascan.php
│   ├── Commands/
│   │   ├── InstallCommand.php
│   │   ├── ScanCommand.php
│   │   └── ListChecksCommand.php
│   ├── Contracts/
│   │   ├── Check.php
│   │   └── ToolRunner.php
│   ├── Support/
│   │   ├── AbstractCheck.php
│   │   ├── Finding.php
│   │   ├── ScanResult.php
│   │   ├── Severity.php
│   │   ├── Category.php
│   │   ├── CheckRegistry.php
│   │   └── FileParser.php
│   ├── Checks/
│   │   ├── Config/
│   │   ├── Cookies/
│   │   ├── Headers/
│   │   ├── Auth/
│   │   ├── Csrf/
│   │   ├── Models/
│   │   ├── Sql/
│   │   ├── Xss/
│   │   ├── Files/
│   │   ├── Injection/
│   │   ├── Crypto/
│   │   ├── Dependencies/
│   │   ├── Php/
│   │   ├── Logging/
│   │   └── Repo/
│   ├── Tools/
│   │   ├── SemgrepRunner.php
│   │   ├── ComposerAuditRunner.php
│   │   ├── NpmAuditRunner.php
│   │   └── PhpStanRunner.php
│   ├── PhpStan/
│   │   ├── RawQueryUserInputRule.php
│   │   ├── UnguardedModelRule.php
│   │   └── ...
│   └── Reporters/
│       └── ConsoleReporter.php
├── tests/
│   ├── Feature/
│   ├── Unit/
│   ├── Integration/
│   └── Fixtures/
├── docs/
│   ├── README.md
│   ├── installation.md
│   ├── configuration.md
│   ├── ci-integration.md
│   ├── checks.md
│   └── checks/
│       └── {category}/{check-id}.md
└── phpstan.neon.dist
```

Notes:
- `src/PhpStan/` holds rule classes shipped to *consumer* projects via the published `phpstan.neon.stub`. `src/Tools/PhpStanRunner.php` is for when larascan invokes PHPStan internally during a scan.
- One file per check, to make per-check enable/disable trivial via config.

## Core contracts

### `Check` interface

```php
interface Check
{
    public function id(): string;              // e.g. 'cookies.session-secure'
    public function category(): Category;
    public function severity(): Severity;
    public function name(): string;
    public function docsUrl(): string;
    public function isApplicable(): bool;

    /** @return iterable<Finding> */
    public function run(): iterable;
}
```

### `Finding` value object

```php
final readonly class Finding
{
    public function __construct(
        public string $checkId,
        public Severity $severity,
        public string $message,
        public ?string $file = null,
        public ?int $line = null,
        public ?string $snippet = null,
    ) {}
}
```

A `Finding`'s severity may override the check's default severity (e.g., a composer-audit check with default `High` may emit a `Critical` finding for a CVSS-9.8 CVE).

### Enums

- `Severity`: `Critical`, `High`, `Medium`, `Low`, `Info`
- `Category`: `Config`, `Cookies`, `Headers`, `Auth`, `Csrf`, `Models`, `Sql`, `Xss`, `Files`, `Injection`, `Crypto`, `Dependencies`, `Php`, `Logging`, `Repo`

### `ScanResult`

Immutable collection of `Finding`s plus per-check status: `passed | failed | skipped | errored`.

### Tool wrappers as checks

Each external tool becomes a single `Check` that yields one `Finding` per advisory/match:

```php
final class ComposerAuditCheck extends AbstractCheck
{
    public function __construct(private ComposerAuditRunner $runner) {}
    public function id(): string { return 'dependencies.composer-audit'; }
    public function severity(): Severity { return Severity::High; }
    public function run(): iterable
    {
        foreach ($this->runner->run() as $advisory) {
            yield new Finding(
                checkId: $this->id(),
                severity: Severity::fromCvssScore($advisory->cvss),
                message: "{$advisory->package} {$advisory->version} — {$advisory->title}",
            );
        }
    }
}
```

## Scan flow

```
ScanCommand
  └─> Larascan::scan(ScanOptions)
        ├─> CheckRegistry::enabled()
        ├─> foreach Check:
        │     ├─> isApplicable() ? continue : skipped
        │     ├─> findings = run()
        │     └─> ScanResult::recordCheck($check, $findings)
        └─> ConsoleReporter::render($result)
              └─> exitCode = $result->maxSeverity() >= options.failOn ? 1 : 0
```

## Configuration

`config/larascan.php`:

```php
return [
    'fail_on' => 'high',

    'checks' => [
        'cookies.session-secure' => ['enabled' => true],
        'dependencies.composer-audit' => ['enabled' => true],
        'dependencies.npm-audit' => ['enabled' => true],
        // ... 70 entries total
    ],

    'ignore' => [
        'tests/Fixtures/*',
    ],

    'tools' => [
        'semgrep' => env('LARASCAN_SEMGREP_BIN', 'semgrep'),
        'npm' => env('LARASCAN_NPM_BIN', 'npm'),
        'timeout' => 60,
    ],

    'baseline' => null, // reserved for v2
];
```

## Commands

### `larascan:install`

1. Detect environment: PHP version, Laravel version, `composer.json`, `package.json`, OS.
2. Verify external tools required by enabled checks:
   - `semgrep --version` — if missing, show install instructions (`brew install semgrep` / `pip install semgrep`).
   - `npm --version` — only required if `package.json` exists.
   - `composer audit` — native, no check needed.
3. Verify composer dev deps: `larastan/larastan` present; offer to add if missing.
4. Publish assets interactively:
   - `config/larascan.php`
   - `.github/workflows/larascan.yml`
   - `.semgrep/larascan.yml`
   - `phpstan-larascan.neon`
5. Summary: which checks become active, which are skipped due to missing deps.

Flags: `--no-interaction`, `--publish=all|config|workflow|semgrep|phpstan`.

### `larascan`

```bash
php artisan larascan                       # all enabled checks
php artisan larascan --fail-on=critical    # override config threshold
php artisan larascan --check=cookies.*     # filter by id prefix
php artisan larascan --category=headers    # filter by category
php artisan larascan --details             # show snippets/lines
php artisan larascan --env=production      # force production-only checks
php artisan larascan --ignore-errors       # exit 0 on errored checks
```

Output (CLI):

```
larascan — security scan

  ✗ cookies.session-secure              CRITICAL   SESSION_SECURE_COOKIE is false
  ✗ headers.csp-defined                 HIGH       No Content-Security-Policy middleware found
  ✓ config.app-debug                    —          APP_DEBUG=false in production
  ⊘ dependencies.npm-audit              —          skipped (no package.json)
  ! sql.raw-user-input                  HIGH       DB::raw($request->input(...)) in app/Http/.../UserController.php:42

Report
  Passed: 47    Failed: 3    Skipped: 2    Errored: 0
  Highest severity: CRITICAL    Threshold: high → exit 1
```

### `larascan:list`

```bash
php artisan larascan:list
php artisan larascan:list --category=auth
php artisan larascan:list --format=markdown  # generates docs/checks.md content
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | No findings ≥ `--fail-on` threshold |
| 1 | Findings ≥ threshold |
| 2 | A check threw an exception (errored) |

## Check inventory (v1 — 70 checks)

### Config (`config.*`) — 9

| Check ID | Severity | What |
|---|---|---|
| `config.app-debug` | Critical | `APP_DEBUG=false` in production |
| `config.app-key` | Critical | `APP_KEY` present and not empty |
| `config.app-env` | High | `APP_ENV` not `local` in production |
| `config.env-not-committed` | Critical | `.env` in `.gitignore` and not in git history |
| `config.env-example-sync` | Low | `.env` and `.env.example` keys in sync |
| `config.env-calls-outside-config` | Medium | No `env()` calls outside `config/*` |
| `config.log-level` | Low | `LOG_LEVEL` not `debug` in production |
| `config.debug-blacklist` | Medium | `debug_blacklist`/`debug_hide` set |
| `config.trusted-proxies` | Medium | `TrustedProxies` not `*` without reason |

### Cookies & sessions (`cookies.*`) — 7

| Check ID | Severity | What |
|---|---|---|
| `cookies.session-secure` | Critical | `SESSION_SECURE_COOKIE=true` in production |
| `cookies.session-http-only` | High | `SESSION_HTTP_ONLY=true` |
| `cookies.session-same-site` | High | `SESSION_SAME_SITE` is `lax` or `strict` |
| `cookies.session-encrypt` | High | Session encryption on (L11+) |
| `cookies.session-lifetime` | Low | Reasonable session lifetime |
| `cookies.encrypt-middleware` | High | `EncryptCookies` middleware active |
| `cookies.encrypt-excludes` | Medium | No sensitive cookies in `$except` |

### Headers (`headers.*`) — 7

| Check ID | Severity | What |
|---|---|---|
| `headers.hsts` | High | HSTS middleware detected |
| `headers.csp-defined` | High | CSP middleware detected |
| `headers.csp-unsafe-inline` | Medium | No `unsafe-inline`/`unsafe-eval` in CSP |
| `headers.x-content-type-options` | Medium | `nosniff` set |
| `headers.x-frame-options` | Medium | XFO or `frame-ancestors` set |
| `headers.referrer-policy` | Low | Referrer-Policy set |
| `headers.cors-wildcard` | High | CORS not `*` with `supports_credentials=true` |

### Auth (`auth.*`) — 6

| Check ID | Severity | What |
|---|---|---|
| `auth.login-throttle` | High | Login route has `throttle` middleware |
| `auth.bcrypt-rounds` | Medium | `BCRYPT_ROUNDS >= 12` or argon2id |
| `auth.password-column-plain` | Critical | No `password` column without hash |
| `auth.sanctum-expiration` | Medium | `sanctum.expiration` is set |
| `auth.signed-routes-verify` | Low | Email verification uses signed routes |
| `auth.api-ability-scoping` | Low | Sanctum tokens have abilities defined |

### CSRF (`csrf.*`) — 2

| Check ID | Severity | What |
|---|---|---|
| `csrf.middleware-disabled` | Critical | `VerifyCsrfToken` not removed from global stack |
| `csrf.except-suspicious` | Medium | No suspicious URIs in `$except` |

### Models (`models.*`) — 4

| Check ID | Severity | What |
|---|---|---|
| `models.unguarded` | High | No `$guarded = []` on Eloquent models |
| `models.unguard-call` | High | No `Model::unguard()` in app code |
| `models.foreign-key-fillable` | Medium | FK columns not in `$fillable` |
| `models.force-fill-user-input` | High | `forceFill()` with request data |

### SQL injection (`sql.*`) — 4 (via PHPStan rules)

| Check ID | Severity | What |
|---|---|---|
| `sql.raw-user-input` | Critical | `DB::raw`/`whereRaw`/`selectRaw` with request data |
| `sql.raw-order-by` | High | `orderByRaw` with user input without allowlist |
| `sql.variable-table-column` | High | Variable table/column name in query |
| `sql.validation-rule-injection` | Medium | Validation rules from request input |

### XSS (`xss.*`) — 3

| Check ID | Severity | What |
|---|---|---|
| `xss.blade-unescaped` | High | `{!! $var !!}` with request-data variables |
| `xss.html-string` | Medium | `new HtmlString(...)` with user input |
| `xss.url-javascript-protocol` | Medium | `href`/`src` with user input without URL validation |

### Files (`files.*`) — 4

| Check ID | Severity | What |
|---|---|---|
| `files.path-traversal` | Critical | `Storage::*`/`File::*` with user-controlled path |
| `files.upload-mimes-validation` | High | Uploads validated via `mimes:` not extension |
| `files.public-executable-uploads` | High | No `.php`/`.phtml` allowed in upload dirs |
| `files.unlink-user-input` | Critical | `unlink()`/`File::delete()` with user input |

### Injection (`injection.*`) — 5

| Check ID | Severity | What |
|---|---|---|
| `injection.command` | Critical | `exec`/`shell_exec`/`system`/`passthru` with variables |
| `injection.process-shell` | High | `Process::fromShellCommandline` without escape |
| `injection.unserialize` | Critical | `unserialize()` on user input |
| `injection.open-redirect` | High | `redirect($request->...)` without allowlist |
| `injection.host-header` | Medium | Trusted hosts not configured |

### Crypto & secrets (`crypto.*`) — 4

| Check ID | Severity | What |
|---|---|---|
| `crypto.weak-hash` | High | `md5`/`sha1` for password/integrity |
| `crypto.weak-random` | High | `rand()`/`mt_rand()` for security tokens |
| `crypto.hardcoded-secret` | Critical | High-entropy strings or known secret patterns in code |
| `crypto.cipher-not-pinned` | Low | `Crypt::decrypt` without cipher pinning |

### Dependencies (`dependencies.*`) — 4

| Check ID | Severity | What |
|---|---|---|
| `dependencies.composer-audit` | High* | `composer audit --format=json` — severity per CVE |
| `dependencies.npm-audit` | High* | `npm audit --json` when `package.json` exists |
| `dependencies.minimum-stability-dev` | Medium | `minimum-stability=dev` in production composer.json |
| `dependencies.outdated-php` | High | PHP version EOL or <6mo before EOL |

\* per-Finding severity derived from CVE data

### PHP & build (`php.*`) — 5

| Check ID | Severity | What |
|---|---|---|
| `php.expose-php` | Low | `expose_php=Off` in php.ini |
| `php.display-errors` | High | `display_errors=Off` in production |
| `php.allow-url-fopen` | Medium | `allow_url_fopen=Off` |
| `php.public-sensitive-files` | Critical | `.env`/`.git`/`*.sql.gz` not in `public/` |
| `php.phpinfo` | Critical | No `phpinfo()` calls in app code |

### Logging (`logging.*`) — 3

| Check ID | Severity | What |
|---|---|---|
| `logging.dd-dump-debug` | Medium | No `dd`/`dump`/`var_dump` in `app/` |
| `logging.custom-error-pages` | Low | Custom 5xx error views present |
| `logging.sensitive-in-log-context` | High | `password`/`token`/`secret` keys in `Log::*([...])` context |

### Repo & CI (`repo.*`) — 3

| Check ID | Severity | What |
|---|---|---|
| `repo.dependabot` | Low | `.github/dependabot.yml` present |
| `repo.gitleaks-history` | High | Known secret patterns in `git log -p` |
| `repo.debug-toolbars` | High | `barryvdh/laravel-debugbar`, Telescope in `require` (not `require-dev`) |

**Total: 70 checks across 15 categories.**

## Published GitHub Actions workflow

`resources/stubs/workflow.yml.stub` — published to `.github/workflows/larascan.yml`:

```yaml
name: larascan security scan

on:
  pull_request:
  push:
    branches: [main]
  schedule:
    - cron: '0 3 * * *'

permissions:
  contents: read

jobs:
  scan:
    name: Security scan
    runs-on: ubuntu-latest

    steps:
      - name: Checkout
        uses: actions/checkout@v6
        with:
          fetch-depth: 0   # required for repo.gitleaks-history

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          tools: composer:v2
          coverage: none

      - name: Setup Node
        uses: actions/setup-node@v4
        with:
          node-version: '20'
        if: hashFiles('package.json') != ''

      - name: Setup Python (for Semgrep)
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install Semgrep
        run: pip install semgrep

      - name: Cache composer dependencies
        uses: actions/cache@v5
        with:
          path: vendor
          key: composer-${{ hashFiles('composer.lock') }}

      - name: Install composer dependencies
        run: composer install --no-interaction --no-progress --prefer-dist

      - name: Run larascan
        run: php artisan larascan --fail-on=high --no-interaction
```

Notes:
- No SARIF upload — v1 is CLI-only. SARIF is v2.
- `fetch-depth: 0` only required for `repo.gitleaks-history`. Documented inline.
- Semgrep via pip — no Docker, faster CI.
- `--fail-on=high` default; consumer can edit after publish.

## Test strategy

```
tests/
├── Unit/
│   ├── Checks/Config/AppDebugCheckTest.php
│   ├── Checks/Cookies/SessionSecureCheckTest.php
│   ├── Support/FindingTest.php
│   └── ...
├── Feature/
│   ├── ScanCommandTest.php
│   ├── InstallCommandTest.php
│   └── PhpStanRulesTest.php
├── Integration/
│   ├── SemgrepRunnerTest.php
│   ├── ComposerAuditRunnerTest.php
│   └── NpmAuditRunnerTest.php
└── Fixtures/
    ├── apps/
    │   ├── secure/
    │   └── vulnerable/
    ├── code/
    │   ├── sql-raw-user-input.php
    │   ├── xss-blade-unescaped.blade.php
    │   └── ...
    └── audits/
```

Per check: at least one positive test (passes) and one negative test (fails with expected severity).

Custom PHPStan rules: PHPStan's `RuleTestCase` against `.php` fixture files, asserting expected error/line tuples.

Tool wrappers: integration tests skip if binary missing locally; CI always installs the binaries.

CI matrix (own `tests.yml`, distinct from the published consumer workflow):

| Job | What |
|---|---|
| `tests` | Pest, PHP 8.2/8.3/8.4 × Laravel 10/11/12/13 |
| `static-analysis` | Larastan level 8 |
| `format` | Pint --test |
| `semgrep-integration` | Pest tests with Semgrep installed |

## Documentation

```
docs/
├── README.md
├── installation.md
├── configuration.md
├── ci-integration.md
├── checks.md                       # auto-generated table of all 70 checks
└── checks/
    ├── config/
    │   ├── app-debug.md
    │   └── ...
    └── ... (one .md per check)
```

Per-check template (max ~30 lines):

```markdown
# {Human name}

**ID:** `{id}`
**Category:** {Category}
**Severity:** {Severity}

## What it checks

{One paragraph}

## Why it matters

{One paragraph — risk and impact}

## How to fix

{Code or env example}

## When this check is skipped

{Skip conditions}

## References

- {OWASP link}
- {Laravel docs link}
```

`larascan:list --format=markdown` regenerates `docs/checks.md` from the registry; CI snapshot-checks it for drift. Each `Check` exposes `docsUrl()` pointing to its `.md`.

README stays short: what + install + first scan + links to docs.

## Edge cases & error handling

| Situation | Behavior |
|---|---|
| Check throws | Status = `errored`; exception stored on `ScanResult`; exit code 2 (overridable with `--ignore-errors`) |
| Missing external tool | `isApplicable()` returns false; status = `skipped` with reason; `larascan:install` warns earlier |
| Tool returns non-parseable output | Tool runner throws `RuntimeException`; check errors out (don't silently report 0 findings) |
| Composer/npm audit network failure | Per-tool timeout (default 60s); on failure → errored, not skipped |
| Empty `glob()` for file scans | Passed if "nothing to scan" is semantically clean (e.g., no views); errored if absence is suspicious (e.g., no `public/`) |
| Production-only check in local env | `isApplicable()` checks env; default skipped locally; `--env=production` forces applicable |
| Symlinks & vendor dirs | `vendor/`, `node_modules/`, `storage/`, `bootstrap/cache/` skipped by default; configurable via `ignore` |
| Symlinks outside project root | Not followed (defense in depth) |
| Memory & duration | No hard cap; FileParser cached per scan-run; tool timeouts only |
| Concurrent runs | Not supported in v1; matrix CI is fine (each has its own working dir) |
| Invalid config | Validated at scan start; clear error with suggestion |

## Out of scope for v1

- SARIF / JSON / Markdown output formats — CLI only
- Baseline (Enlightn-style)
- Runtime / HTTP probing (TLS, live headers, defacement) — see repo-sec as a reference for a separate concern
- Auto-fix functionality
- Web UI / dashboard
- Pro tier / commercial license — OSS only
- Concurrent scan execution
