# Changelog

All notable changes to `baspa/larascan` will be documented in this file.

## [2.1.0] — 2026-05-16

### Added

- New `larascan:advise` command surfacing heuristic security advisories without gating CI (always exits 0).
- `advise.signed-url-user-context` — signed URLs without user-bound route parameters.
- `advise.password-reset-mfa` — password-reset routes without MFA middleware.
- `advise.broadcast-channels-flags` — broadcast channels surfaced for manual authorization review.
- `advise.outdated-packages` — direct-outdated composer and npm packages (shell-out).
- `advise.config-validated-at-boot` — no service provider throws on missing critical config.
- `advise.livewire-public-properties` — Livewire components with public properties lacking `protected $rules` or `#[Validate]` attributes.
- `advise.staging-key-in-production` — test-prefixed API keys present alongside `APP_ENV=production`.
- New `docs/manual-security-checklist.md` covering architectural items LaraScan cannot detect (2FA on sensitive actions, MFA recovery, early authorization, email-verification flows).

All new advisories were inspired by [securinglaravel.com](https://securinglaravel.com/).

## [2.0.0] — 2026-05-16

### Added

- New `Routing` category.
- `routing.state-mutating-get` — flag GET routes whose controller method is `destroy`/`delete`/`remove`/`deactivate`/`disable`.
- `routing.api-http-only` — flag API routes without HTTPS-enforcing middleware when `APP_URL` is `http://`. Severity downgrades outside production.
- `auth.signed-url-no-params` — flag `URL::signedRoute()` / `URL::temporarySignedRoute()` calls without route parameters.
- `auth.otp-rate-limiting` — flag OTP/2FA verification routes without `throttle:` middleware.
- `auth.registration-rate-limit` — flag registration routes without `throttle:` middleware. Severity downgrades outside production.
- `auth.jwt-missing-expiration` — flag Tymon JWT installations where `config('jwt.ttl')` is null or 0.
- `headers.csp-base-uri` — flag Spatie CSP policies that do not set a `base-uri` directive.
- `sql.orwhere-scope-bypass` — flag `->orWhere(...)` chained directly off `->where(...)` outside a closure group.
- `xss.htmlstring-cast` — flag Eloquent casts using `HtmlString::class`.
- `crypto.password-self-generated` — flag weak generators (`Str::random`, `md5`, `uniqid`, `random_bytes`, `bin2hex`) used in password contexts.
- `repo.security-txt` — flag missing `public/.well-known/security.txt`.

All new checks were inspired by [securinglaravel.com](https://securinglaravel.com/).

## [1.0.0] - 2026-05-15

### Initial release

Security-focused static analysis for Laravel applications. 70 checks across 15 categories.

**Categories:**
- Application config (9 checks)
- Cookies & sessions (7)
- HTTP headers (7, two gated on `spatie/laravel-csp`)
- Authentication (6, some gated on `laravel/sanctum`)
- CSRF (2)
- Eloquent models (4)
- SQL injection (4)
- XSS (3)
- File handling (4)
- Injection (5)
- Crypto & secrets (4)
- Dependencies (4, wrappers for composer/npm audit)
- PHP & build (5)
- Logging & errors (3)
- Repo & CI (3)

**Tooling:**
- Hybrid implementation: own analyzers + wrappers for `composer audit`, `npm audit`, `semgrep`, `phpstan`
- Production-aware severity downgrade for env-sensitive checks
- Publishable GitHub Actions workflow
- PHPStan level 8 + Pint clean
- Laravel 10 / 11 / 12 / 13 supported, PHP 8.2+

**Commands:**
- `larascan` — run scan with `--fail-on`, `--check=`, `--category=`, `--ignore-errors`
- `larascan:list` — list registered checks
- `larascan:install` — publish config + (optional) workflow + verify environment

See README for full check inventory.
