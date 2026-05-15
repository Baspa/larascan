<p align="center">
    <img src="art/larascan-logo.png" alt="LaraScan — Scan Laravel applications for vulnerabilities, insecure configs and risky code">
</p>

# LaraScan

Security-focused static analysis for Laravel applications. One artisan command, ~70 checks across config, cookies, headers, auth, models, SQL, XSS, files, injection, crypto, dependencies and more.

> **Status:** Pre-1.0 — Phase 6 (Auth, CSRF, Models, PHP, Logging, Repo checks) complete. See [docs/superpowers/plans](docs/superpowers/plans) for roadmap.

## Install

```bash
composer require baspa/larascan --dev
php artisan larascan:install
```

## Usage

```bash
php artisan larascan                  # run all enabled checks
php artisan larascan --category=config
php artisan larascan --fail-on=high   # CI threshold
php artisan larascan:list             # list registered checks
```

After installing, the following checks are available by default:

**Config (`config.*`)**
- `config.app-debug` — APP_DEBUG must be false in production
- `config.app-key` — APP_KEY must be set
- `config.app-env` — APP_ENV must not be a development value in production
- `config.env-not-committed` — .env must be gitignored and never committed
- `config.env-example-sync` — .env and .env.example must share key sets
- `config.env-calls-outside-config` — env() calls outside config/ defeat config caching
- `config.log-level` — Default log channel must not be at debug in production
- `config.debug-blacklist` — debug_blacklist must redact sensitive env keys when debug is on
- `config.trusted-proxies` — Trusted proxies must not be wildcard

**Cookies & sessions (`cookies.*`)**
- `cookies.session-secure` — SESSION_SECURE_COOKIE must be true in production
- `cookies.session-http-only` — SESSION_HTTP_ONLY must be true
- `cookies.session-same-site` — SESSION_SAME_SITE must be lax or strict
- `cookies.session-encrypt` — session.encrypt should be true
- `cookies.session-lifetime` — session.lifetime must be within a reasonable range
- `cookies.encrypt-middleware` — EncryptCookies middleware must be registered
- `cookies.encrypt-excludes` — Sensitive cookies must not be in EncryptCookies::$except

**Headers (`headers.*`)**
- `headers.cors-wildcard` — CORS allowed_origins must not be wildcard with credentials enabled
- `headers.hsts` — HSTS header middleware must be active in production
- `headers.x-content-type-options` — X-Content-Type-Options: nosniff middleware must be active
- `headers.x-frame-options` — X-Frame-Options or frame-ancestors must be set
- `headers.referrer-policy` — Referrer-Policy header middleware should be active
- `headers.csp-defined` — CSP middleware must be active (requires `spatie/laravel-csp`)
- `headers.csp-unsafe-inline` — CSP must not use unsafe-inline or unsafe-eval (requires `spatie/laravel-csp`)

**Auth (`auth.*`)**
- `auth.bcrypt-rounds` — BCRYPT_ROUNDS must be 12 or higher
- `auth.sanctum-expiration` — Sanctum tokens must have an expiration (requires `laravel/sanctum`)
- `auth.login-throttle` — Login routes must have throttle middleware
- `auth.password-column-plain` — User model must hide or hash the password column
- `auth.signed-routes-verify` — Email verification routes must use signed middleware
- `auth.api-ability-scoping` — Sanctum tokens must be created with explicit abilities (requires `laravel/sanctum`)

**CSRF (`csrf.*`)**
- `csrf.middleware-disabled` — VerifyCsrfToken middleware must be registered
- `csrf.except-suspicious` — CSRF except list must not contain wildcard patterns

**Models (`models.*`)**
- `models.unguarded` — Eloquent models must not use `$guarded = []`
- `models.unguard-call` — No static `Model::unguard()` calls in application code
- `models.foreign-key-fillable` — Foreign key columns should not be in `$fillable`
- `models.force-fill-user-input` — `forceFill()` calls bypass mass-assignment protection

**PHP (`php.*`)**
- `php.expose-php` — expose_php must be off
- `php.display-errors` — display_errors must be off in production
- `php.allow-url-fopen` — allow_url_fopen should be off
- `php.public-sensitive-files` — No .env / .git / .sql backups in public/
- `php.phpinfo` — No phpinfo() calls in application code

**Logging (`logging.*`)**
- `logging.dd-dump-debug` — No dd() / dump() / var_dump() in application code
- `logging.custom-error-pages` — resources/views/errors/500.blade.php and 503.blade.php must exist
- `logging.sensitive-in-log-context` — Log context arrays must not contain password/token/secret keys

**Repo & CI (`repo.*`)**
- `repo.dependabot` — .github/dependabot.yml should exist for automated dep updates
- `repo.gitleaks-history` — No high-entropy secrets in git history (last 100 commits)
- `repo.debug-toolbars` — Debug packages (debugbar, telescope) must be in require-dev only

**Dependencies (`dependencies.*`)**
- `dependencies.composer-audit` — wraps `composer audit` for PHP CVE detection
- `dependencies.npm-audit` — wraps `npm audit` when a `package.json` is present

## Documentation

- [Design spec](docs/superpowers/specs/2026-05-15-larascan-design.md)
- Per-check documentation lives under `docs/checks/` (added in Phase 7).

## Requirements

- PHP 8.2+
- Laravel 10 / 11 / 12 / 13

## License

MIT
