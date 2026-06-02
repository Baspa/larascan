<p align="center">
    <img src="art/larascan-logo.png" alt="LaraScan — Scan Laravel applications for vulnerabilities, insecure configs and risky code">
</p>

# LaraScan

[![Latest Version](https://img.shields.io/packagist/v/baspa/larascan.svg?style=flat-square)](https://packagist.org/packages/baspa/larascan)
[![Tests](https://img.shields.io/github/actions/workflow/status/baspa/larascan/tests.yml?branch=main&label=tests&style=flat-square)](https://github.com/baspa/larascan/actions/workflows/tests.yml)
[![PHPStan](https://img.shields.io/github/actions/workflow/status/baspa/larascan/phpstan.yml?branch=main&label=phpstan%20level%208&style=flat-square)](https://github.com/baspa/larascan/actions/workflows/phpstan.yml)
[![Coverage](https://img.shields.io/codecov/c/github/baspa/larascan?style=flat-square)](https://codecov.io/gh/baspa/larascan)
[![Downloads](https://img.shields.io/packagist/dt/baspa/larascan.svg?style=flat-square)](https://packagist.org/packages/baspa/larascan)
[![License](https://img.shields.io/packagist/l/baspa/larascan.svg?style=flat-square)](LICENSE.md)

Security-focused static analysis for Laravel applications. One artisan command, **81 checks** across config, cookies, headers, auth, routing, models, SQL, XSS, files, injection, crypto, dependencies and more.

> **Why LaraScan?** Most Laravel security issues come from misconfiguration or forgotten dev settings in production — debug on, secure cookies off, hardcoded API keys in code. LaraScan scans for them in one shot, AST-based where it matters, with sane defaults and a clean CI workflow.

## Example

```
larascan security scan
════════════════════════════════════════════

  Application configuration
  ─────────────────────────
     ✗ config.app-env
        └─ INFO     APP_ENV is 'local' — leaks development-mode behavior in production.
     ✗ config.env-example-sync
        ├─ LOW      Keys present in .env but missing from .env.example: MISTRAL_API_KEY
        └─ LOW      Keys present in .env.example but missing from .env: RESPONSE_CACHE_*

  Cookies & sessions
  ──────────────────
     ✗ cookies.session-encrypt
        └─ HIGH     session.encrypt is false — session payloads are stored in plaintext.

════════════════════════════════════════════
  Report Card
════════════════════════════════════════════

  Application configuration ███████████░░░░░░░░░  57%   (4/7)
  Cookies & sessions       ██████████████░░░░░░  71%   (5/7)
  HTTP headers             ████░░░░░░░░░░░░░░░░  20%   (1/5)
  ...

  Total: 45 passed   19 failed   6 skipped   0 errored
  Highest severity: CRITICAL
```

## Install

```bash
composer require baspa/larascan --dev
php artisan larascan:install
```

The install command publishes `config/larascan.php` and optionally `.github/workflows/larascan.yml` (CI workflow stub).

## Usage

```bash
php artisan larascan                  # run all enabled checks
php artisan larascan --only-failed    # hide passed + skipped
php artisan larascan --category=config
php artisan larascan --fail-on=high   # CI threshold (exit 1 on findings ≥ high)
php artisan larascan:list             # list all registered checks
```

### Advise (heuristic, non-gating)

```bash
php artisan larascan:advise                  # surface heuristic security advisories
php artisan larascan:advise --advice=advise.auth.*
php artisan larascan:advise --category=auth
```

Advise is intentionally non-gating: exit code is always 0. For architectural items that no scanner can detect, see [`docs/manual-security-checklist.md`](docs/manual-security-checklist.md).

### Output formats

| Flag | Default for | Description |
|---|---|---|
| (none) | TTY / humans | Categorized output with a Report Card at the end |
| `--format=json` | AI agents | Structured JSON. Auto-selected when [`laravel/agent-detector`](https://github.com/laravel/agent-detector) flags the run as an agent (Claude Code, Cursor, Codex, Copilot, etc.). |

Force JSON manually with `LARASCAN_AGENT_MODE=1` or `--format=json`.

## Configuration

Published `config/larascan.php` controls:

- `fail_on` — severity threshold for non-zero exit code (`critical|high|medium|low|info`, default `high`)
- `checks` — per-check enable map (`'cookies.session-secure' => ['enabled' => false]`)
- `ignore` — glob patterns to skip during AST scans
- `tools` — override binary paths via env vars: `LARASCAN_COMPOSER_BIN`, `LARASCAN_NPM_BIN`, `LARASCAN_SEMGREP_BIN`

See [docs/configuration.md](docs/configuration.md) for full details.

## CI integration

The published workflow runs on PR + push to main + nightly. It uses `--only-failed` to keep CI logs lean, with the Report Card at the end for the overview.

```bash
php artisan larascan:install --workflow
```

Exit codes: `0` clean, `1` findings ≥ `--fail-on`, `2` a check errored. See [docs/ci-integration.md](docs/ci-integration.md).

## What's checked?

81 checks across 16 categories. Some require optional packages — those checks self-skip when the package isn't installed.

<details>
<summary><strong>Show all 81 checks</strong></summary>

**Config (`config.*`)** — 9
- `config.app-debug` — APP_DEBUG must be false in production
- `config.app-key` — APP_KEY must be set
- `config.app-env` — APP_ENV must not be a development value in production
- `config.env-not-committed` — .env must be gitignored and never committed
- `config.env-example-sync` — .env and .env.example must share key sets
- `config.env-calls-outside-config` — env() calls outside config/ defeat config caching
- `config.log-level` — Default log channel must not be at debug in production
- `config.debug-blacklist` — debug_blacklist must redact sensitive env keys when debug is on
- `config.trusted-proxies` — Trusted proxies must not be wildcard

**Cookies & sessions (`cookies.*`)** — 7
- `cookies.session-secure` — SESSION_SECURE_COOKIE must be true in production
- `cookies.session-http-only` — SESSION_HTTP_ONLY must be true
- `cookies.session-same-site` — SESSION_SAME_SITE must be lax or strict
- `cookies.session-encrypt` — session.encrypt should be true
- `cookies.session-lifetime` — session.lifetime must be within a reasonable range
- `cookies.encrypt-middleware` — EncryptCookies middleware must be registered
- `cookies.encrypt-excludes` — Sensitive cookies must not be in EncryptCookies::$except

**Headers (`headers.*`)** — 8
- `headers.cors-wildcard` — CORS allowed_origins must not be wildcard with credentials enabled
- `headers.hsts` — HSTS header middleware must be active in production
- `headers.x-content-type-options` — X-Content-Type-Options: nosniff middleware must be active
- `headers.x-frame-options` — X-Frame-Options or frame-ancestors must be set
- `headers.referrer-policy` — Referrer-Policy header middleware should be active
- `headers.csp-defined` — CSP middleware must be active *(requires [spatie/laravel-csp](https://github.com/spatie/laravel-csp))*
- `headers.csp-unsafe-inline` — CSP must not use unsafe-inline or unsafe-eval *(requires spatie/laravel-csp)*
- `headers.csp-base-uri` — Spatie CSP policy must include a `base-uri` directive

**Auth (`auth.*`)** — 10
- `auth.bcrypt-rounds` — BCRYPT_ROUNDS must be 12 or higher
- `auth.sanctum-expiration` — Sanctum tokens must have an expiration *(requires [laravel/sanctum](https://github.com/laravel/sanctum))*
- `auth.login-throttle` — Login routes must have throttle middleware
- `auth.password-column-plain` — User model must hide or hash the password column
- `auth.signed-routes-verify` — Email verification routes must use signed middleware
- `auth.api-ability-scoping` — Sanctum tokens must be created with explicit abilities *(requires laravel/sanctum)*
- `auth.signed-url-no-params` — Signed URLs must include user-bound route parameters
- `auth.otp-rate-limiting` — OTP/2FA verification routes must have `throttle:` middleware
- `auth.registration-rate-limit` — Registration routes must have `throttle:` middleware
- `auth.jwt-missing-expiration` — Tymon JWT `jwt.ttl` must not be null or 0

**CSRF (`csrf.*`)** — 2
- `csrf.middleware-disabled` — VerifyCsrfToken middleware must be registered
- `csrf.except-suspicious` — CSRF except list must not contain wildcard patterns

**Routing (`routing.*`)** — 2
- `routing.state-mutating-get` — GET routes must not invoke `destroy`/`delete`/`remove`/`deactivate`/`disable` controller methods
- `routing.api-http-only` — API routes under `api/*` must enforce HTTPS when `APP_URL` is `http://`

**Models (`models.*`)** — 4
- `models.unguarded` — Eloquent models must not use `$guarded = []`
- `models.unguard-call` — No static `Model::unguard()` calls in application code
- `models.foreign-key-fillable` — Foreign key columns should not be in `$fillable`
- `models.force-fill-user-input` — `forceFill()` calls bypass mass-assignment protection

**SQL (`sql.*`)** — 5
- `sql.raw-user-input` — DB::raw / whereRaw / selectRaw with user input
- `sql.raw-order-by` — orderByRaw with user input
- `sql.variable-table-column` — Variable arguments to DB::table / from / select
- `sql.validation-rule-injection` — Validation rules from variable source
- `sql.orwhere-scope-bypass` — `->orWhere(...)` must not be chained directly off `->where(...)` outside a closure group

**XSS (`xss.*`)** — 4
- `xss.blade-unescaped` — Blade `{!! $var !!}` with PHP variables risks XSS
- `xss.html-string` — `Illuminate\Support\HtmlString` produces unescaped HTML
- `xss.url-javascript-protocol` — `javascript:` URLs in href/src are XSS sinks
- `xss.htmlstring-cast` — Eloquent `$casts` / `casts()` must not cast attributes to `HtmlString::class`

**Files (`files.*`)** — 4
- `files.path-traversal` — Storage/File operations with user-controlled paths
- `files.unlink-user-input` — `unlink()`/`rmdir()` in application code
- `files.upload-mimes-validation` — Validation by extension rather than MIME
- `files.public-executable-uploads` — Upload rules allowing .php/.phtml/.phar

**Injection (`injection.*`)** — 5
- `injection.command` — `exec`/`shell_exec`/`system`/`passthru` calls
- `injection.process-shell` — `Process::fromShellCommandline()` usage
- `injection.unserialize` — `unserialize()` of any input
- `injection.open-redirect` — `redirect()` with user-controlled URL
- `injection.host-header` — `app.url` missing or pointing to localhost

**Crypto & secrets (`crypto.*`)** — 5
- `crypto.weak-hash` — md5/sha1 for security purposes
- `crypto.weak-random` — rand/mt_rand/uniqid for security tokens
- `crypto.cipher-not-pinned` — `config/app.php` does not pin the cipher
- `crypto.hardcoded-secret` — High-entropy secrets or known token patterns in code
- `crypto.password-self-generated` — Weak generators (`Str::random`, `md5`, `uniqid`, `random_bytes`, `bin2hex`) must not be used in password contexts — use `Str::password()`

**Dependencies (`dependencies.*`)** — 4
- `dependencies.composer-audit` — wraps `composer audit` for PHP CVE detection
- `dependencies.npm-audit` — wraps `npm audit` when a `package.json` is present
- `dependencies.minimum-stability-dev` — composer.json minimum-stability is 'dev' without prefer-stable
- `dependencies.outdated-php` — PHP version at or near end-of-life

**PHP (`php.*`)** — 5
- `php.expose-php` — expose_php must be off
- `php.display-errors` — display_errors must be off in production
- `php.allow-url-fopen` — allow_url_fopen should be off
- `php.public-sensitive-files` — No .env / .git / .sql backups in public/
- `php.phpinfo` — No `phpinfo()` calls in application code

**Logging (`logging.*`)** — 3
- `logging.dd-dump-debug` — No `dd()` / `dump()` / `var_dump()` in application code
- `logging.custom-error-pages` — `resources/views/errors/500.blade.php` and `503.blade.php` must exist
- `logging.sensitive-in-log-context` — Log context arrays must not contain password/token/secret keys

**Repo & CI (`repo.*`)** — 4
- `repo.dependabot` — `.github/dependabot.yml` should exist for automated dep updates
- `repo.gitleaks-history` — No high-entropy secrets in git history (last 100 commits)
- `repo.debug-toolbars` — Debug packages (debugbar, telescope) must be in `require-dev` only
- `repo.security-txt` — `public/.well-known/security.txt` should exist so researchers know how to report issues

</details>

## Requirements

- PHP 8.3+
- Laravel 11 / 12 / 13

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Tests must pass, PHPStan must be clean at level 8, Pint must be clean.

## Security

If you discover a security issue, please email hello@baspa.dev instead of opening a public issue.

## Inspired by

- [Enlightn](https://github.com/enlightn/enlightn) — the original Laravel performance + security scanner. Its analyzer-per-check pattern and report card concept shaped how LaraScan is structured.
- [Securing Laravel](https://securinglaravel.com/) — Stephen Rees-Carter's writing and newsletter, the practical reference for what to check and why it matters.

## License

The MIT License (MIT). See [LICENSE.md](LICENSE.md).
