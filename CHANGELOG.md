# Changelog

All notable changes to `baspa/larascan` will be documented in this file.

## [2.2.0] — Unreleased

### Added

- **SARIF reporter.** `larascan --format=sarif --output=larascan.sarif` emits a SARIF 2.1.0 report (one result per finding) for GitHub Code Scanning. Any format can now be written to a file with `--output=PATH`.
- **Baseline support.** New `larascan:baseline` command writes current findings to `larascan-baseline.json`; subsequent `larascan` runs suppress baselined findings (counted as `N baselined`, not hidden) so only *new* findings count toward `--fail-on`. Baseline identity is line-insensitive — a finding is hashed from its check id, file and normalized message, so line shifts don't break the baseline. Stale entries are reported with a hint to re-run the command.
  - `larascan --baseline=PATH` — override the baseline path (resolution order: flag > `config('larascan.baseline')` > implicit `larascan-baseline.json` if present).
  - `larascan --no-baseline` — ignore any baseline file.
- **Runtime probe.** New `larascan:probe` command sends one real HTTP GET to the running app and verifies security headers/cookie flags are actually present in the response (catches middleware not running or a proxy stripping headers). New `probe.*` check ids, distinct from the static `headers.*` checks. Checks HSTS, X-Content-Type-Options, X-Frame-Options, Referrer-Policy, CSP, cookie `Secure`/`HttpOnly`/`SameSite`, `Server`/`X-Powered-By` disclosure, and the http→https redirect. Findings against local targets (`localhost`/`127.0.0.1`/`*.test`/`*.local`) downgrade to Info. Flags: `--url`, `--fail-on`, `--probe=*`, `--timeout`, `--insecure`, `--ignore-errors`, `--only-failed`, `--format`. URL resolves from `--url` > `config('larascan.probe.url')` (env `LARASCAN_PROBE_URL`) > `app.url`.
- New `Ecosystem` category.
- `ecosystem.telescope-production` — Telescope enabled in production without an explicit `viewTelescope` gate.
- `ecosystem.horizon-gate` — trivially-true `viewHorizon` gate, or no gate defined in production.
- `ecosystem.pulse-gate` — trivially-true `viewPulse` gate, or no gate defined in production.
- `ecosystem.debugbar-enabled` — Debugbar enabled at runtime in production.
- `ecosystem.livewire-upload-rules` — Livewire temporary upload rules missing a `max:` size or with throttling middleware removed.
- `files.disk-visibility` — public-visibility filesystem disk with a sensitive name/root, or s3 disk with no explicit visibility.
- `config.mail-smtp-encryption` — remote SMTP mailer not forcing TLS.
- `advise.webhook-signature` — POST webhook/callback routes without signature-verification middleware (non-gating advisory).

All new checks were inspired by [securinglaravel.com](https://securinglaravel.com/).

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
