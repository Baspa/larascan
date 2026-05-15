<p align="center">
    <img src="art/larascan-logo.png" alt="LaraScan — Scan Laravel applications for vulnerabilities, insecure configs and risky code">
</p>

# LaraScan

Security-focused static analysis for Laravel applications. One artisan command, ~70 checks across config, cookies, headers, auth, models, SQL, XSS, files, injection, crypto, dependencies and more.

> **Status:** Pre-1.0 — Phase 2 (Tool wrappers) complete. See [docs/superpowers/plans](docs/superpowers/plans) for roadmap.

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

- `config.app-debug` — APP_DEBUG must be false in production
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
