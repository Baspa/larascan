<p align="center">
    <img src="art/larascan-logo.png" alt="LaraScan — Scan Laravel applications for vulnerabilities, insecure configs and risky code">
</p>

# LaraScan

Security-focused static analysis for Laravel applications. One artisan command, ~70 checks across config, cookies, headers, auth, models, SQL, XSS, files, injection, crypto, dependencies and more.

> **Status:** Pre-1.0 — Phase 4 (Cookies checks) complete. See [docs/superpowers/plans](docs/superpowers/plans) for roadmap.

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
