# Changelog

All notable changes to `baspa/larascan` will be documented in this file.

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
