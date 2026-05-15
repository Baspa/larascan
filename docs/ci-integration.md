# CI integration

larascan ships a GitHub Actions workflow stub that runs nightly and on every PR.

## Publish the workflow

```bash
php artisan larascan:install --workflow
```

Or:
```bash
php artisan vendor:publish --tag=larascan-workflow
```

This writes `.github/workflows/larascan.yml`. The workflow:

- Triggers on push to main, every PR, and daily at 03:00 UTC
- Sets up PHP 8.4, composer:v2, optionally Node 20 (if `package.json` exists)
- Caches composer deps
- Runs `php artisan larascan --fail-on=high`

## Exit codes

| Code | Meaning |
|---|---|
| 0   | No findings at or above `--fail-on` threshold |
| 1   | Findings ≥ threshold (CI fails) |
| 2   | A check errored (e.g., binary missing); fix or pass `--ignore-errors` |

## Other CI systems

The artisan command is environment-agnostic. For GitLab/Bitbucket/CircleCI, just run `php artisan larascan --fail-on=high` in a job after `composer install`.

## AI agent integration

larascan auto-detects when an AI agent runs it and emits JSON for easier parsing. To force JSON manually:

```bash
php artisan larascan --format=json
```

The JSON shape:

```json
{
  "version": "1.0",
  "summary": {
    "passed": 24, "failed": 3, "skipped": 2, "errored": 0,
    "highest_severity": "critical"
  },
  "checks": [
    {
      "id": "cookies.session-secure",
      "category": "cookies",
      "status": "failed",
      "findings": [
        {"severity": "critical", "message": "...", "file": "app/...", "line": 42}
      ]
    }
  ]
}
```
