# Configuration

`config/larascan.php` controls which checks run and how. Publish it with:

```bash
php artisan larascan:install
```

## Top-level keys

### `fail_on`
Severity threshold above which the scan exits non-zero. Values: `critical`, `high`, `medium`, `low`, `info`. Default: `high`.

### `checks`
Per-check enable map. Each key is a check ID like `config.app-debug`. Set `enabled => false` to disable. Missing entries default to enabled.

```php
'checks' => [
    'dependencies.composer-audit' => ['enabled' => true],
    'cookies.session-lifetime' => ['enabled' => false],
],
```

### `ignore`
Glob patterns of files/dirs to skip during AST-based scans. Default skips `vendor`, `node_modules`, `storage`, `bootstrap/cache`.

### `tools`
Override binary paths for external tools:
- `composer` — defaults to `composer` (env: `LARASCAN_COMPOSER_BIN`)
- `npm` — defaults to `npm` (env: `LARASCAN_NPM_BIN`)
- `semgrep` — defaults to `semgrep` (env: `LARASCAN_SEMGREP_BIN`)

### `baseline`
Reserved for future use (v1.1+).

## Production-aware severities

Some checks (e.g. `config.app-env`, `cookies.session-secure`) downgrade their finding severity to `Info` when `APP_ENV` is not `production`. This avoids dev/test noise. Run with `APP_ENV=production` to see the real severity profile.
