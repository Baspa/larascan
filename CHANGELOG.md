# Changelog

All notable changes to `baspa/larascan` will be documented in this file.

Some versions were tagged twice on the same commit (`v2.1.0` and `v3.0.0`, `v3.0.1` and `v3.1.0`, `v3.0.2` and `v3.1.1`). Each such release is listed once below under its higher number.

## [Unreleased]

## [3.1.4] — 2026-11-12

### Security

- **`larascan:probe` no longer sends URL credentials over plain HTTP.** When probing `https://user:pass@host`, the http→https redirect check re-sent the credentials in cleartext. Userinfo is now stripped from that request and from the "Probing …" line printed to the console and CI logs. The redirect request is therefore unauthenticated: a host that sits entirely behind basic auth answers it with a 401 rather than a redirect.
- **Console output no longer renders scanned text raw.** File names, finding messages, skip reasons and errors are stripped of control characters and have formatter tags escaped before they are written in the human format, so a crafted file name (for example under `public/uploads`) can no longer spoof or hide scanner output. Newlines and tabs in those strings show as a single space. JSON and SARIF output are unchanged.

## [3.1.3] — 2026-09-20

### Changed

- `guzzlehttp/guzzle` constraint is now `^7.8||^8.0`, so Guzzle 8 is allowed while Laravel 12 (whose `illuminate/http` requires Guzzle 7) keeps installing.

## [3.1.2] — 2026-07-27

### Fixed

- **`headers.csp-defined` no longer fires when a subclass of `AddCspHeaders` is registered.** Apps commonly subclass it to skip the policy on routes they don't control (Horizon, Pulse), and the subclass name need not contain `AddCspHeaders`, so the check reported a missing policy that was in fact active. Detection now also matches by inheritance.
- **`headers.hsts` no longer fires when a differently-named middleware sets the header.** No package owns `Strict-Transport-Security`, so the middleware can be called anything — `SecurityHeaders` is a common choice and matched none of the keywords. When name matching fails, the check now reads the registered middleware for the header name itself.
- **`xss.blade-unescaped` no longer flags output that is already sanitized.** `{!! strip_tags($slot) !!}` is Laravel's own published plain-text mail layout, so every app that publishes the mail views inherited four high-severity findings it could not act on — the body is `text/plain`, and escaping it would emit a literal `&amp;`. Whole-expression calls to `strip_tags`, `e`, `htmlspecialchars` and `htmlentities` are now skipped; a sanitizer concatenated with raw output is still reported.

## [3.1.1] — 2026-06-25

Also tagged `v3.0.2`.

### Fixed

- **`csrf.middleware-disabled` no longer raises a critical false positive on Laravel 11 and later.** The check only matched the name `VerifyCsrfToken`, but the CSRF middleware has shipped as `VerifyCsrfToken` (Laravel 10 and earlier), `ValidateCsrfToken` (11 and 12) and `PreventRequestForgery` (13 and later, in the default `web` group). All three names are now detected, and the check name and finding message are version-neutral.

## [3.1.0] — 2026-06-16

Also tagged `v3.0.1`.

### Fixed

- **Scan memory is bounded.** A full scan peaked around 650 MB on a medium app, because every file-scanning check was built with its own `FileParser` and the same `app/` files were parsed and held in memory once per check. All checks now share a single parser cache, so each file is parsed once.
- **A PHP out-of-memory no longer ends the scan in a silent exit 255.** The scan raises `memory_limit` to a 512M floor when the configured limit is lower, and a shutdown handler turns a fatal error or OOM into a clear diagnostic on stderr.

### Added

- Memory-limit hint in the published GitHub Actions workflow stub.
- Security policy (`.github/SECURITY.md`).

### Changed

- Workflow actions in this repository's CI are pinned to commit SHAs.

## [3.0.0] — 2026-06-11

Also tagged `v2.1.0`.

### Changed

- **Breaking: Laravel 11 is no longer supported.** `illuminate/*` now requires `^12.0||^13.0`, and `symfony/process` and `symfony/yaml` require `^7.0||^8.0`. PHP 8.3+ is still required.
- New runtime dependencies: `illuminate/http` and `guzzlehttp/guzzle` (used by the probe).
- The published workflow stub now runs `--format=sarif --output=larascan.sarif` and uploads the result to GitHub Code Scanning (needs `security-events: write`; the upload step is non-blocking).

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

## [2.0.1] — 2026-06-02

### Fixed

- Updated the `laravel/agent-detector` import to the v2 namespace (`Laravel\AgentDetector\`); the previous import made PHPStan fail once the package was required at `^2.0`.

### Changed

- `laravel/agent-detector` requirement raised from `^1.0` to `^2.0`.
- **Support matrix trimmed to what the toolchain can run:** PHP 8.3+ is required (PHP 8.2 dropped) and Laravel 10 is no longer supported (`^11.0||^12.0||^13.0`). Pest 4 needs PHP 8.3 and its Laravel plugin needs Laravel 11, so the dropped combinations could not install their test dependencies.

## [2.0.0] — 2026-05-17

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

All new checks and advisories were inspired by [securinglaravel.com](https://securinglaravel.com/).

## [1.1.1] — 2026-05-15

### Changed

- Slim, text-only severity labels in the human output, replacing background-color badges that had inconsistent padding.
- The ✗ glyph is colored by the highest finding severity.
- AST checks no longer repeat `file:line` in finding messages; the reporter adds the location automatically.

### Removed

- Dead `statusGlyph()` method from `ConsoleReporter`.

No behavior changes: same 70 checks, same exit codes.

## [1.1.0] — 2026-05-15

### Added

- Enlightn-style categorized human output: per-category sections, severity labels, and a Report Card with a progress bar per category.
- `--only-failed` flag hides passed and skipped checks. The published CI workflow uses it by default.
- `--format=json` output with structured findings, summary and metadata.
- AI-agent auto-detection via `laravel/agent-detector` (Claude Code, Cursor, Codex, Devin, Replit, Augment, Copilot and others) switches to JSON output automatically; set `LARASCAN_AGENT_MODE=1` to force it.

### Changed

- The `termwind` dependency was dropped in favour of plain Symfony Console ANSI styling.

Same 70 checks, same severity behavior, same exit codes.

## [1.0.0] — 2026-05-15

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

[Unreleased]: https://github.com/Baspa/larascan/compare/v3.1.4...HEAD
[3.1.4]: https://github.com/Baspa/larascan/compare/v3.1.3...v3.1.4
[3.1.3]: https://github.com/Baspa/larascan/compare/v3.1.2...v3.1.3
[3.1.2]: https://github.com/Baspa/larascan/compare/v3.1.1...v3.1.2
[3.1.1]: https://github.com/Baspa/larascan/compare/v3.1.0...v3.1.1
[3.1.0]: https://github.com/Baspa/larascan/compare/v3.0.0...v3.1.0
[3.0.0]: https://github.com/Baspa/larascan/compare/v2.0.1...v3.0.0
[2.0.1]: https://github.com/Baspa/larascan/compare/v2.0.0...v2.0.1
[2.0.0]: https://github.com/Baspa/larascan/compare/v1.1.1...v2.0.0
[1.1.1]: https://github.com/Baspa/larascan/compare/v1.1.0...v1.1.1
[1.1.0]: https://github.com/Baspa/larascan/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Baspa/larascan/releases/tag/v1.0.0
