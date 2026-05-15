# Larascan Foundation — Implementation Plan (Phase 1 of 8)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Commit policy:** The user has explicit feedback `feedback-no-auto-commit`. Commits below are INTENDED commit points, not autonomous actions. Pause at every `git commit` step and let the user run it themselves (or explicitly confirm).

**Goal:** Convert the Spatie skeleton in `~/Sites/larascan/` into a working `baspa/larascan` package with the full core architecture wired up and one end-to-end working check (`config.app-debug`). After this plan, `php artisan larascan` runs, scans, and reports.

**Architecture:** Single PHP 8.2+ package. Service-provider auto-discovery wires up commands and binds the `Larascan` orchestrator. Checks implement the `Check` contract and are auto-registered into a `CheckRegistry` from the namespace `Baspa\Larascan\Checks`. `Finding` value objects flow from `Check::run()` through `Larascan::scan()` into a `ScanResult`, then rendered by `ConsoleReporter`. PHPStan level 8 from day one.

**Tech Stack:** PHP 8.2+, Laravel 10/11/12/13, Pest 4, Orchestra Testbench, spatie/laravel-package-tools, larastan ^3, nikic/php-parser, symfony/process.

**Spec reference:** `docs/superpowers/specs/2026-05-15-larascan-design.md`

**Future plans (NOT in scope here):**
- Phase 2: Tool wrappers (Semgrep, ComposerAudit, NpmAudit, PhpStan runners + their Check classes)
- Phase 3: Config + Cookies + Headers checks (23 checks)
- Phase 4: Auth + CSRF + PHP + Models + Logging + Repo checks (~23 checks)
- Phase 5: AST-based checks (XSS, Files, Injection, Crypto)
- Phase 6: Custom PHPStan rules (SQL injection)
- Phase 7: Per-check documentation (70 pages)
- Phase 8: Publishable stubs (workflow.yml, semgrep.yml, phpstan.neon) + full InstallCommand

---

## File map (created/modified in this plan)

**Replaced (skeleton → real):**
- `composer.json` (rewritten)
- `phpstan.neon.dist` (level 8)
- `README.md`
- `tests/TestCase.php` (namespace + provider rename)
- `tests/Pest.php` (namespace rename)

**Deleted (skeleton leftovers):**
- `src/Skeleton.php`
- `src/SkeletonServiceProvider.php`
- `src/Commands/SkeletonCommand.php`
- `src/Facades/Skeleton.php`
- `tests/ArchTest.php`
- `tests/ExampleTest.php`
- `database/` (whole dir — no models in this package)
- `resources/` (whole dir for now — re-created in Phase 8)
- `config/skeleton.php`
- `configure.php`
- `phpstan-baseline.neon`

**Created:**
- `src/LarascanServiceProvider.php`
- `src/Larascan.php`
- `src/Facades/Larascan.php`
- `src/Support/Severity.php`
- `src/Support/Category.php`
- `src/Support/Finding.php`
- `src/Support/ScanResult.php`
- `src/Support/CheckStatus.php`
- `src/Support/ScanOptions.php`
- `src/Support/AbstractCheck.php`
- `src/Support/CheckRegistry.php`
- `src/Support/FileParser.php`
- `src/Contracts/Check.php`
- `src/Commands/ScanCommand.php`
- `src/Commands/ListChecksCommand.php`
- `src/Commands/InstallCommand.php`
- `src/Reporters/ConsoleReporter.php`
- `src/Checks/Config/AppDebugCheck.php`
- `config/larascan.php`
- `tests/Unit/Support/SeverityTest.php`
- `tests/Unit/Support/CategoryTest.php`
- `tests/Unit/Support/FindingTest.php`
- `tests/Unit/Support/ScanResultTest.php`
- `tests/Unit/Support/CheckRegistryTest.php`
- `tests/Unit/Support/FileParserTest.php`
- `tests/Unit/Reporters/ConsoleReporterTest.php`
- `tests/Unit/Checks/Config/AppDebugCheckTest.php`
- `tests/Feature/ScanCommandTest.php`
- `tests/Feature/ListChecksCommandTest.php`
- `tests/Feature/InstallCommandTest.php`
- `.github/workflows/tests.yml` (replaces skeleton's)
- `.github/workflows/phpstan.yml` (rewritten)

---

## Task 1: Package metadata + skeleton cleanup

**Files:**
- Modify: `composer.json`
- Modify: `tests/TestCase.php`
- Modify: `tests/Pest.php`
- Delete: skeleton files (see file map)

- [ ] **Step 1: Delete the skeleton-specific source and resources**

```bash
cd /Users/basvandinther/Sites/larascan
rm -rf src/Skeleton.php \
       src/SkeletonServiceProvider.php \
       src/Commands/SkeletonCommand.php \
       src/Facades/Skeleton.php \
       tests/ArchTest.php \
       tests/ExampleTest.php \
       database \
       resources \
       config/skeleton.php \
       configure.php \
       phpstan-baseline.neon
```

- [ ] **Step 2: Replace `composer.json` with the real package metadata**

```json
{
    "name": "baspa/larascan",
    "description": "A security-focused static analysis package for Laravel applications",
    "keywords": ["laravel", "security", "static-analysis", "sast", "scanner"],
    "homepage": "https://github.com/baspa/larascan",
    "license": "MIT",
    "authors": [
        {
            "name": "Bas van Dinther",
            "email": "bas@ux.nl",
            "role": "Developer"
        }
    ],
    "require": {
        "php": "^8.2",
        "illuminate/contracts": "^10.0||^11.0||^12.0||^13.0",
        "illuminate/console": "^10.0||^11.0||^12.0||^13.0",
        "illuminate/support": "^10.0||^11.0||^12.0||^13.0",
        "spatie/laravel-package-tools": "^1.16",
        "nikic/php-parser": "^5.0",
        "symfony/process": "^6.4||^7.0",
        "symfony/yaml": "^6.4||^7.0"
    },
    "require-dev": {
        "larastan/larastan": "^3.0",
        "laravel/pint": "^1.14",
        "nunomaduro/collision": "^8.0",
        "orchestra/testbench": "^8.0||^9.0||^10.0||^11.0",
        "pestphp/pest": "^4.0",
        "pestphp/pest-plugin-laravel": "^4.0",
        "phpstan/extension-installer": "^1.4",
        "phpstan/phpstan-deprecation-rules": "^2.0",
        "phpstan/phpstan-phpunit": "^2.0"
    },
    "autoload": {
        "psr-4": {
            "Baspa\\Larascan\\": "src/"
        }
    },
    "autoload-dev": {
        "psr-4": {
            "Baspa\\Larascan\\Tests\\": "tests/"
        }
    },
    "scripts": {
        "post-autoload-dump": "@composer run prepare",
        "prepare": "@php vendor/bin/testbench package:discover --ansi",
        "analyse": "vendor/bin/phpstan analyse",
        "test": "vendor/bin/pest",
        "test-coverage": "vendor/bin/pest --coverage",
        "format": "vendor/bin/pint"
    },
    "config": {
        "sort-packages": true,
        "allow-plugins": {
            "pestphp/pest-plugin": true,
            "phpstan/extension-installer": true
        }
    },
    "extra": {
        "laravel": {
            "providers": [
                "Baspa\\Larascan\\LarascanServiceProvider"
            ],
            "aliases": {
                "Larascan": "Baspa\\Larascan\\Facades\\Larascan"
            }
        }
    },
    "minimum-stability": "stable",
    "prefer-stable": true
}
```

- [ ] **Step 3: Update `tests/TestCase.php` to the new namespace and provider**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tests;

use Baspa\Larascan\LarascanServiceProvider;
use Orchestra\Testbench\TestCase as Orchestra;

class TestCase extends Orchestra
{
    /**
     * @param  \Illuminate\Foundation\Application  $app
     * @return array<int, class-string>
     */
    protected function getPackageProviders($app): array
    {
        return [
            LarascanServiceProvider::class,
        ];
    }
}
```

- [ ] **Step 4: Update `tests/Pest.php`**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Tests\TestCase;

uses(TestCase::class)->in(__DIR__);
```

- [ ] **Step 5: Reinstall dependencies and dump autoload**

```bash
rm -rf vendor composer.lock
composer install --no-interaction --prefer-dist
```

Expected: "Generating optimized autoload files" and no errors. (Will fail later on `package:discover` because `LarascanServiceProvider` doesn't exist yet — that's OK; we add it in Task 9. For now run with `--no-scripts` if needed.)

If `composer install` fails on `package:discover`, run:

```bash
composer install --no-interaction --prefer-dist --no-scripts
```

- [ ] **Step 6: Commit point**

```bash
git add -A
git commit -m "chore: rename skeleton to baspa/larascan and remove unused scaffolding"
```

(**Pause: ask user before running this commit.**)

---

## Task 2: PHPStan level 8 setup

**Files:**
- Modify: `phpstan.neon.dist`
- Create: `tests/Unit/PHPStanLevelTest.php` (snapshot test — guards level regressions)

- [ ] **Step 1: Replace `phpstan.neon.dist` with a level 8 config**

```neon
parameters:
    level: 8
    paths:
        - src
        - config
    tmpDir: build/phpstan
    treatPhpDocTypesAsCertain: false
    checkMissingIterableValueType: true
    checkGenericClassInNonGenericObjectType: true
```

- [ ] **Step 2: Write a small Pest test that pins the PHPStan level**

```php
<?php

declare(strict_types=1);

use Symfony\Component\Yaml\Yaml;

it('keeps PHPStan analysis at level 8', function () {
    $config = file_get_contents(__DIR__ . '/../../phpstan.neon.dist');
    expect($config)->toContain('level: 8');
});
```

Save as `tests/Unit/PHPStanLevelTest.php` — but Pest expects unit tests not to need the TestCase setup. Move to `tests/Unit/PHPStanLevelTest.php` and ensure Pest.php picks up Unit/ as well (it already does via `->in(__DIR__)`).

- [ ] **Step 3: Run PHPStan and Pest to verify both pass**

```bash
vendor/bin/phpstan analyse --memory-limit=1G --no-progress
vendor/bin/pest tests/Unit/PHPStanLevelTest.php
```

Expected:
- PHPStan: `[OK] No errors` (src/ is mostly empty so trivially passes)
- Pest: 1 passed

- [ ] **Step 4: Commit point**

```bash
git add phpstan.neon.dist tests/Unit/PHPStanLevelTest.php
git commit -m "chore: enable PHPStan level 8"
```

(**Pause: ask user.**)

---

## Task 3: Severity & Category enums

**Files:**
- Create: `src/Support/Severity.php`
- Create: `src/Support/Category.php`
- Test: `tests/Unit/Support/SeverityTest.php`
- Test: `tests/Unit/Support/CategoryTest.php`

- [ ] **Step 1: Write failing test for `Severity`**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Support\Severity;

it('exposes the five severity levels', function () {
    expect(Severity::cases())->toHaveCount(5)
        ->and(Severity::Critical->value)->toBe('critical')
        ->and(Severity::High->value)->toBe('high')
        ->and(Severity::Medium->value)->toBe('medium')
        ->and(Severity::Low->value)->toBe('low')
        ->and(Severity::Info->value)->toBe('info');
});

it('orders severities by rank', function () {
    expect(Severity::Critical->rank())->toBeGreaterThan(Severity::High->rank())
        ->and(Severity::High->rank())->toBeGreaterThan(Severity::Medium->rank())
        ->and(Severity::Medium->rank())->toBeGreaterThan(Severity::Low->rank())
        ->and(Severity::Low->rank())->toBeGreaterThan(Severity::Info->rank());
});

it('compares severities with isAtLeast', function () {
    expect(Severity::Critical->isAtLeast(Severity::High))->toBeTrue()
        ->and(Severity::Low->isAtLeast(Severity::High))->toBeFalse();
});

it('derives severity from CVSS score', function () {
    expect(Severity::fromCvssScore(9.5))->toBe(Severity::Critical)
        ->and(Severity::fromCvssScore(7.5))->toBe(Severity::High)
        ->and(Severity::fromCvssScore(4.5))->toBe(Severity::Medium)
        ->and(Severity::fromCvssScore(2.0))->toBe(Severity::Low)
        ->and(Severity::fromCvssScore(0.0))->toBe(Severity::Info);
});
```

Save as `tests/Unit/Support/SeverityTest.php`.

- [ ] **Step 2: Run, see it fail**

```bash
vendor/bin/pest tests/Unit/Support/SeverityTest.php
```

Expected: Class `Baspa\Larascan\Support\Severity` not found.

- [ ] **Step 3: Implement `Severity`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

enum Severity: string
{
    case Critical = 'critical';
    case High = 'high';
    case Medium = 'medium';
    case Low = 'low';
    case Info = 'info';

    public function rank(): int
    {
        return match ($this) {
            self::Critical => 5,
            self::High => 4,
            self::Medium => 3,
            self::Low => 2,
            self::Info => 1,
        };
    }

    public function isAtLeast(self $other): bool
    {
        return $this->rank() >= $other->rank();
    }

    public static function fromCvssScore(float $score): self
    {
        return match (true) {
            $score >= 9.0 => self::Critical,
            $score >= 7.0 => self::High,
            $score >= 4.0 => self::Medium,
            $score >= 0.1 => self::Low,
            default => self::Info,
        };
    }
}
```

Save as `src/Support/Severity.php`.

- [ ] **Step 4: Verify tests pass + PHPStan clean**

```bash
vendor/bin/pest tests/Unit/Support/SeverityTest.php
vendor/bin/phpstan analyse src/Support/Severity.php --no-progress
```

Expected: 4 passed, PHPStan OK.

- [ ] **Step 5: Write failing test for `Category`**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Support\Category;

it('exposes the fifteen categories', function () {
    expect(Category::cases())->toHaveCount(15);
});

it('exposes human labels', function () {
    expect(Category::Cookies->label())->toBe('Cookies & sessions')
        ->and(Category::Headers->label())->toBe('HTTP headers');
});
```

Save as `tests/Unit/Support/CategoryTest.php`.

- [ ] **Step 6: Implement `Category`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

enum Category: string
{
    case Config = 'config';
    case Cookies = 'cookies';
    case Headers = 'headers';
    case Auth = 'auth';
    case Csrf = 'csrf';
    case Models = 'models';
    case Sql = 'sql';
    case Xss = 'xss';
    case Files = 'files';
    case Injection = 'injection';
    case Crypto = 'crypto';
    case Dependencies = 'dependencies';
    case Php = 'php';
    case Logging = 'logging';
    case Repo = 'repo';

    public function label(): string
    {
        return match ($this) {
            self::Config => 'Application configuration',
            self::Cookies => 'Cookies & sessions',
            self::Headers => 'HTTP headers',
            self::Auth => 'Authentication',
            self::Csrf => 'CSRF',
            self::Models => 'Eloquent models',
            self::Sql => 'SQL queries',
            self::Xss => 'XSS',
            self::Files => 'File handling',
            self::Injection => 'Injection',
            self::Crypto => 'Crypto & secrets',
            self::Dependencies => 'Dependencies',
            self::Php => 'PHP & build',
            self::Logging => 'Logging & errors',
            self::Repo => 'Repo & CI',
        };
    }
}
```

Save as `src/Support/Category.php`.

- [ ] **Step 7: Verify**

```bash
vendor/bin/pest tests/Unit/Support
vendor/bin/phpstan analyse --no-progress
```

Expected: All green.

- [ ] **Step 8: Commit point**

```bash
git add src/Support tests/Unit/Support
git commit -m "feat: add Severity and Category enums"
```

(**Pause: ask user.**)

---

## Task 4: Finding & ScanResult value objects

**Files:**
- Create: `src/Support/Finding.php`
- Create: `src/Support/CheckStatus.php`
- Create: `src/Support/ScanResult.php`
- Test: `tests/Unit/Support/FindingTest.php`
- Test: `tests/Unit/Support/ScanResultTest.php`

- [ ] **Step 1: Write failing test for `Finding`**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

it('constructs a finding with the required fields', function () {
    $finding = new Finding(
        checkId: 'cookies.session-secure',
        severity: Severity::Critical,
        message: 'SESSION_SECURE_COOKIE is false',
    );

    expect($finding->checkId)->toBe('cookies.session-secure')
        ->and($finding->severity)->toBe(Severity::Critical)
        ->and($finding->file)->toBeNull()
        ->and($finding->line)->toBeNull();
});

it('accepts file and line for location-aware findings', function () {
    $finding = new Finding(
        checkId: 'sql.raw-user-input',
        severity: Severity::High,
        message: 'DB::raw with user input',
        file: 'app/Http/Controllers/UserController.php',
        line: 42,
    );

    expect($finding->file)->toBe('app/Http/Controllers/UserController.php')
        ->and($finding->line)->toBe(42);
});
```

Save as `tests/Unit/Support/FindingTest.php`.

- [ ] **Step 2: Run, see it fail**

```bash
vendor/bin/pest tests/Unit/Support/FindingTest.php
```

Expected: Class not found.

- [ ] **Step 3: Implement `Finding`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

final readonly class Finding
{
    public function __construct(
        public string $checkId,
        public Severity $severity,
        public string $message,
        public ?string $file = null,
        public ?int $line = null,
        public ?string $snippet = null,
    ) {
    }
}
```

Save as `src/Support/Finding.php`.

- [ ] **Step 4: Verify Finding tests pass**

```bash
vendor/bin/pest tests/Unit/Support/FindingTest.php
```

Expected: 2 passed.

- [ ] **Step 5: Implement `CheckStatus` enum (no test — simple enum)**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

enum CheckStatus: string
{
    case Passed = 'passed';
    case Failed = 'failed';
    case Skipped = 'skipped';
    case Errored = 'errored';
}
```

Save as `src/Support/CheckStatus.php`.

- [ ] **Step 6: Write failing test for `ScanResult`**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanResult;
use Baspa\Larascan\Support\Severity;

it('records check statuses and findings', function () {
    $result = new ScanResult();
    $result = $result
        ->record('a.passed', CheckStatus::Passed, [])
        ->record('b.failed', CheckStatus::Failed, [
            new Finding('b.failed', Severity::High, 'oops'),
        ])
        ->record('c.skipped', CheckStatus::Skipped, [], 'no package.json');

    expect($result->counts())->toBe([
        'passed' => 1,
        'failed' => 1,
        'skipped' => 1,
        'errored' => 0,
    ]);

    expect($result->findings())->toHaveCount(1)
        ->and($result->statusOf('c.skipped'))->toBe(CheckStatus::Skipped)
        ->and($result->skipReasonOf('c.skipped'))->toBe('no package.json');
});

it('reports the highest severity seen', function () {
    $result = new ScanResult();
    $result = $result->record('x', CheckStatus::Failed, [
        new Finding('x', Severity::Medium, 'a'),
        new Finding('x', Severity::Critical, 'b'),
    ]);

    expect($result->highestSeverity())->toBe(Severity::Critical);
});

it('reports null highest severity when no findings', function () {
    $result = new ScanResult();
    expect($result->highestSeverity())->toBeNull();
});

it('records an errored check with exception class and message', function () {
    $result = new ScanResult();
    $result = $result->recordError('z', new \RuntimeException('boom'));

    expect($result->counts()['errored'])->toBe(1)
        ->and($result->errorOf('z'))->toBe('RuntimeException: boom');
});
```

Save as `tests/Unit/Support/ScanResultTest.php`.

- [ ] **Step 7: Implement `ScanResult` (immutable, builder-style)**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Throwable;

final class ScanResult
{
    /**
     * @param array<string, CheckStatus> $statuses
     * @param array<int, Finding> $findings
     * @param array<string, string> $skipReasons
     * @param array<string, string> $errors
     */
    public function __construct(
        private array $statuses = [],
        private array $findings = [],
        private array $skipReasons = [],
        private array $errors = [],
    ) {
    }

    /**
     * @param iterable<Finding> $findings
     */
    public function record(string $checkId, CheckStatus $status, iterable $findings, ?string $skipReason = null): self
    {
        $statuses = $this->statuses;
        $statuses[$checkId] = $status;

        $allFindings = $this->findings;
        foreach ($findings as $f) {
            $allFindings[] = $f;
        }

        $skipReasons = $this->skipReasons;
        if ($skipReason !== null) {
            $skipReasons[$checkId] = $skipReason;
        }

        return new self($statuses, $allFindings, $skipReasons, $this->errors);
    }

    public function recordError(string $checkId, Throwable $e): self
    {
        $statuses = $this->statuses;
        $statuses[$checkId] = CheckStatus::Errored;

        $errors = $this->errors;
        $errors[$checkId] = $e::class . ': ' . $e->getMessage();

        return new self($statuses, $this->findings, $this->skipReasons, $errors);
    }

    public function statusOf(string $checkId): ?CheckStatus
    {
        return $this->statuses[$checkId] ?? null;
    }

    public function skipReasonOf(string $checkId): ?string
    {
        return $this->skipReasons[$checkId] ?? null;
    }

    public function errorOf(string $checkId): ?string
    {
        return $this->errors[$checkId] ?? null;
    }

    /**
     * @return array<int, Finding>
     */
    public function findings(): array
    {
        return $this->findings;
    }

    /**
     * @return array<string, int>
     */
    public function counts(): array
    {
        $counts = ['passed' => 0, 'failed' => 0, 'skipped' => 0, 'errored' => 0];
        foreach ($this->statuses as $status) {
            $counts[$status->value]++;
        }
        return $counts;
    }

    public function highestSeverity(): ?Severity
    {
        $highest = null;
        foreach ($this->findings as $f) {
            if ($highest === null || $f->severity->isAtLeast($highest)) {
                $highest = $f->severity;
            }
        }
        return $highest;
    }

    /**
     * @return array<string, CheckStatus>
     */
    public function statuses(): array
    {
        return $this->statuses;
    }
}
```

Save as `src/Support/ScanResult.php`.

- [ ] **Step 8: Verify all Support tests + PHPStan pass**

```bash
vendor/bin/pest tests/Unit/Support
vendor/bin/phpstan analyse --no-progress
```

Expected: All green.

- [ ] **Step 9: Commit point**

```bash
git add src/Support tests/Unit/Support
git commit -m "feat: add Finding, CheckStatus and ScanResult value objects"
```

(**Pause: ask user.**)

---

## Task 5: Check interface + AbstractCheck base

**Files:**
- Create: `src/Contracts/Check.php`
- Create: `src/Support/AbstractCheck.php`

- [ ] **Step 1: Create `Check` contract (interface — no tests needed)**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Contracts;

use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;

interface Check
{
    public function id(): string;

    public function category(): Category;

    public function severity(): Severity;

    public function name(): string;

    public function docsUrl(): string;

    public function isApplicable(): bool;

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable;
}
```

Save as `src/Contracts/Check.php`.

- [ ] **Step 2: Implement `AbstractCheck` with sensible defaults**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Baspa\Larascan\Contracts\Check;

abstract class AbstractCheck implements Check
{
    public function isApplicable(): bool
    {
        return true;
    }

    public function docsUrl(): string
    {
        [$cat, $id] = explode('.', $this->id(), 2);
        return "https://github.com/baspa/larascan/blob/main/docs/checks/{$cat}/{$id}.md";
    }
}
```

Save as `src/Support/AbstractCheck.php`.

- [ ] **Step 3: Run PHPStan to verify level 8 compliance**

```bash
vendor/bin/phpstan analyse --no-progress
```

Expected: `[OK] No errors`.

- [ ] **Step 4: Commit point**

```bash
git add src/Contracts src/Support/AbstractCheck.php
git commit -m "feat: add Check contract and AbstractCheck base"
```

(**Pause: ask user.**)

---

## Task 6: CheckRegistry

**Files:**
- Create: `src/Support/CheckRegistry.php`
- Test: `tests/Unit/Support/CheckRegistryTest.php`

Purpose: holds the canonical list of registered Check instances. Filters by config (`enabled` flags), category, or ID prefix. In Phase 1 we only need explicit registration via `register()` — auto-discovery from a namespace can wait.

- [ ] **Step 1: Write failing test**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Contracts\Check;
use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\CheckRegistry;
use Baspa\Larascan\Support\Severity;

final class FakeCheck extends AbstractCheck
{
    public function __construct(
        private string $id,
        private Category $category,
        private Severity $severity = Severity::Medium,
    ) {
    }

    public function id(): string { return $this->id; }
    public function category(): Category { return $this->category; }
    public function severity(): Severity { return $this->severity; }
    public function name(): string { return 'fake'; }

    /** @return iterable<\Baspa\Larascan\Support\Finding> */
    public function run(): iterable { return []; }
}

it('registers and lists checks', function () {
    $registry = new CheckRegistry();
    $registry->register(new FakeCheck('config.a', Category::Config));
    $registry->register(new FakeCheck('cookies.b', Category::Cookies));

    expect($registry->all())->toHaveCount(2);
});

it('filters checks by ID pattern with wildcard', function () {
    $registry = new CheckRegistry();
    $registry->register(new FakeCheck('cookies.a', Category::Cookies));
    $registry->register(new FakeCheck('cookies.b', Category::Cookies));
    $registry->register(new FakeCheck('config.x', Category::Config));

    $matched = iterator_to_array($registry->matching(['cookies.*']));
    expect($matched)->toHaveCount(2);
});

it('filters checks by category', function () {
    $registry = new CheckRegistry();
    $registry->register(new FakeCheck('config.a', Category::Config));
    $registry->register(new FakeCheck('headers.b', Category::Headers));

    $matched = iterator_to_array($registry->forCategory(Category::Headers));
    expect($matched)->toHaveCount(1);
});

it('honors enabled config to exclude checks', function () {
    $registry = new CheckRegistry(config: [
        'cookies.b' => ['enabled' => false],
    ]);
    $registry->register(new FakeCheck('cookies.a', Category::Cookies));
    $registry->register(new FakeCheck('cookies.b', Category::Cookies));

    expect($registry->enabled())->toHaveCount(1);
});

it('throws on duplicate registration', function () {
    $registry = new CheckRegistry();
    $registry->register(new FakeCheck('a', Category::Config));

    expect(fn () => $registry->register(new FakeCheck('a', Category::Config)))
        ->toThrow(InvalidArgumentException::class, 'already registered');
});
```

Save as `tests/Unit/Support/CheckRegistryTest.php`.

- [ ] **Step 2: Run, see it fail**

```bash
vendor/bin/pest tests/Unit/Support/CheckRegistryTest.php
```

Expected: `CheckRegistry` not found.

- [ ] **Step 3: Implement `CheckRegistry`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use Baspa\Larascan\Contracts\Check;
use InvalidArgumentException;

final class CheckRegistry
{
    /** @var array<string, Check> */
    private array $checks = [];

    /**
     * @param array<string, array{enabled?: bool}> $config
     */
    public function __construct(
        private readonly array $config = [],
    ) {
    }

    public function register(Check $check): void
    {
        $id = $check->id();
        if (isset($this->checks[$id])) {
            throw new InvalidArgumentException("Check '{$id}' is already registered.");
        }
        $this->checks[$id] = $check;
    }

    /**
     * @return array<int, Check>
     */
    public function all(): array
    {
        return array_values($this->checks);
    }

    /**
     * @return array<int, Check>
     */
    public function enabled(): array
    {
        return array_values(array_filter(
            $this->checks,
            fn (Check $c) => ($this->config[$c->id()]['enabled'] ?? true) === true,
        ));
    }

    /**
     * @param array<int, string> $patterns
     * @return iterable<Check>
     */
    public function matching(array $patterns): iterable
    {
        foreach ($this->checks as $id => $check) {
            foreach ($patterns as $pattern) {
                $regex = '/^' . str_replace('\\*', '.*', preg_quote($pattern, '/')) . '$/';
                if (preg_match($regex, $id) === 1) {
                    yield $check;
                    continue 2;
                }
            }
        }
    }

    /**
     * @return iterable<Check>
     */
    public function forCategory(Category $category): iterable
    {
        foreach ($this->checks as $check) {
            if ($check->category() === $category) {
                yield $check;
            }
        }
    }
}
```

Save as `src/Support/CheckRegistry.php`.

- [ ] **Step 4: Verify**

```bash
vendor/bin/pest tests/Unit/Support/CheckRegistryTest.php
vendor/bin/phpstan analyse --no-progress
```

Expected: 5 passed, PHPStan OK.

- [ ] **Step 5: Commit point**

```bash
git add src/Support/CheckRegistry.php tests/Unit/Support/CheckRegistryTest.php
git commit -m "feat: add CheckRegistry with filtering and enable/disable"
```

(**Pause: ask user.**)

---

## Task 7: FileParser helper

**Files:**
- Create: `src/Support/FileParser.php`
- Test: `tests/Unit/Support/FileParserTest.php`

Purpose: thin wrapper around `nikic/php-parser` that caches parsed ASTs per scan run. Phase 1 only needs the cache + a single `parse(string $path): ?array` API; AST checks come in Phase 5.

- [ ] **Step 1: Write failing test**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Support\FileParser;

it('parses a php file into a node list', function () {
    $path = __DIR__ . '/fixtures/simple.php';
    @mkdir(dirname($path), 0755, true);
    file_put_contents($path, "<?php\necho 'hi';\n");

    $parser = new FileParser();
    $ast = $parser->parse($path);

    expect($ast)->toBeArray()->and($ast)->not->toBeEmpty();
    unlink($path);
});

it('returns null on syntax error', function () {
    $path = __DIR__ . '/fixtures/broken.php';
    @mkdir(dirname($path), 0755, true);
    file_put_contents($path, "<?php\nthis is not php\n");

    $parser = new FileParser();
    $ast = $parser->parse($path);

    expect($ast)->toBeNull();
    unlink($path);
});

it('caches parsed AST per path', function () {
    $path = __DIR__ . '/fixtures/cached.php';
    @mkdir(dirname($path), 0755, true);
    file_put_contents($path, "<?php\necho 1;\n");

    $parser = new FileParser();
    $first = $parser->parse($path);

    file_put_contents($path, "<?php\necho 2;\n"); // mutate after first parse
    $second = $parser->parse($path);

    expect($second)->toBe($first); // same array → cache hit
    unlink($path);
});
```

Save as `tests/Unit/Support/FileParserTest.php`.

- [ ] **Step 2: Run, see it fail**

```bash
vendor/bin/pest tests/Unit/Support/FileParserTest.php
```

- [ ] **Step 3: Implement `FileParser`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

use PhpParser\Error;
use PhpParser\Node;
use PhpParser\Parser;
use PhpParser\ParserFactory;

final class FileParser
{
    private readonly Parser $parser;

    /** @var array<string, array<int, Node>|null> */
    private array $cache = [];

    public function __construct()
    {
        $this->parser = (new ParserFactory())->createForHostVersion();
    }

    /**
     * @return array<int, Node>|null
     */
    public function parse(string $path): ?array
    {
        if (array_key_exists($path, $this->cache)) {
            return $this->cache[$path];
        }

        $source = @file_get_contents($path);
        if ($source === false) {
            return $this->cache[$path] = null;
        }

        try {
            $ast = $this->parser->parse($source);
        } catch (Error) {
            return $this->cache[$path] = null;
        }

        return $this->cache[$path] = $ast;
    }
}
```

Save as `src/Support/FileParser.php`.

- [ ] **Step 4: Verify + PHPStan**

```bash
vendor/bin/pest tests/Unit/Support/FileParserTest.php
vendor/bin/phpstan analyse --no-progress
```

Expected: 3 passed, PHPStan OK.

- [ ] **Step 5: Commit point**

```bash
git add src/Support/FileParser.php tests/Unit/Support/FileParserTest.php
git commit -m "feat: add cached FileParser around nikic/php-parser"
```

(**Pause: ask user.**)

---

## Task 8: ConsoleReporter

**Files:**
- Create: `src/Reporters/ConsoleReporter.php`
- Test: `tests/Unit/Reporters/ConsoleReporterTest.php`

Purpose: renders a `ScanResult` to a Symfony `OutputInterface`. Reasonable bare implementation — pretty formatting can be polished in Phase 8.

- [ ] **Step 1: Write failing test**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Reporters\ConsoleReporter;
use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanResult;
use Baspa\Larascan\Support\Severity;
use Symfony\Component\Console\Output\BufferedOutput;

it('renders a passed, failed and skipped row plus summary', function () {
    $result = (new ScanResult())
        ->record('config.app-debug', CheckStatus::Passed, [])
        ->record('cookies.session-secure', CheckStatus::Failed, [
            new Finding('cookies.session-secure', Severity::Critical, 'SESSION_SECURE_COOKIE is false'),
        ])
        ->record('dependencies.npm-audit', CheckStatus::Skipped, [], 'no package.json');

    $output = new BufferedOutput();
    (new ConsoleReporter())->render($result, $output);

    $text = $output->fetch();
    expect($text)
        ->toContain('config.app-debug')
        ->toContain('cookies.session-secure')
        ->toContain('CRITICAL')
        ->toContain('SESSION_SECURE_COOKIE is false')
        ->toContain('dependencies.npm-audit')
        ->toContain('skipped (no package.json)')
        ->toContain('Passed: 1')
        ->toContain('Failed: 1')
        ->toContain('Skipped: 1');
});
```

Save as `tests/Unit/Reporters/ConsoleReporterTest.php`.

- [ ] **Step 2: Run, see it fail**

```bash
vendor/bin/pest tests/Unit/Reporters/ConsoleReporterTest.php
```

- [ ] **Step 3: Implement `ConsoleReporter`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Reporters;

use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanResult;
use Symfony\Component\Console\Output\OutputInterface;

final class ConsoleReporter
{
    public function render(ScanResult $result, OutputInterface $output): void
    {
        $output->writeln('');
        $output->writeln('<info>larascan — security scan</info>');
        $output->writeln('');

        $findingsByCheck = [];
        foreach ($result->findings() as $f) {
            $findingsByCheck[$f->checkId][] = $f;
        }

        foreach ($result->statuses() as $checkId => $status) {
            $output->writeln(match ($status) {
                CheckStatus::Passed => sprintf('  <fg=green>✓</> %-40s passed', $checkId),
                CheckStatus::Failed => $this->renderFailures($checkId, $findingsByCheck[$checkId] ?? []),
                CheckStatus::Skipped => sprintf(
                    '  <fg=yellow>⊘</> %-40s skipped (%s)',
                    $checkId,
                    $result->skipReasonOf($checkId) ?? 'unknown',
                ),
                CheckStatus::Errored => sprintf(
                    '  <fg=red>!</> %-40s ERROR — %s',
                    $checkId,
                    $result->errorOf($checkId) ?? 'unknown',
                ),
            });
        }

        $counts = $result->counts();
        $output->writeln('');
        $output->writeln('<info>Report</info>');
        $output->writeln(sprintf(
            '  Passed: %d    Failed: %d    Skipped: %d    Errored: %d',
            $counts['passed'],
            $counts['failed'],
            $counts['skipped'],
            $counts['errored'],
        ));
    }

    /**
     * @param array<int, Finding> $findings
     */
    private function renderFailures(string $checkId, array $findings): string
    {
        if ($findings === []) {
            return sprintf('  <fg=red>✗</> %-40s FAILED', $checkId);
        }

        $lines = [];
        foreach ($findings as $f) {
            $lines[] = sprintf(
                '  <fg=red>✗</> %-40s %s   %s',
                $checkId,
                strtoupper($f->severity->value),
                $f->message,
            );
        }
        return implode("\n", $lines);
    }
}
```

Save as `src/Reporters/ConsoleReporter.php`.

- [ ] **Step 4: Verify + PHPStan**

```bash
vendor/bin/pest tests/Unit/Reporters/ConsoleReporterTest.php
vendor/bin/phpstan analyse --no-progress
```

Expected: 1 passed, PHPStan OK.

- [ ] **Step 5: Commit point**

```bash
git add src/Reporters tests/Unit/Reporters
git commit -m "feat: add ConsoleReporter for CLI output"
```

(**Pause: ask user.**)

---

## Task 9: Larascan orchestrator + ScanOptions

**Files:**
- Create: `src/Support/ScanOptions.php`
- Create: `src/Larascan.php`

Purpose: the main entry point. Wires together a `CheckRegistry`, applies `ScanOptions` filters, runs each check, wraps exceptions, and returns a `ScanResult`.

- [ ] **Step 1: Implement `ScanOptions` (simple immutable data holder — no tests, it's just a struct)**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Support;

final readonly class ScanOptions
{
    /**
     * @param array<int, string> $checkPatterns  e.g. ['cookies.*']
     */
    public function __construct(
        public Severity $failOn = Severity::High,
        public array $checkPatterns = [],
        public ?Category $category = null,
    ) {
    }
}
```

Save as `src/Support/ScanOptions.php`.

- [ ] **Step 2: Implement `Larascan` orchestrator**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan;

use Baspa\Larascan\Contracts\Check;
use Baspa\Larascan\Support\CheckRegistry;
use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanOptions;
use Baspa\Larascan\Support\ScanResult;
use Throwable;

final class Larascan
{
    public function __construct(
        private readonly CheckRegistry $registry,
    ) {
    }

    public function registry(): CheckRegistry
    {
        return $this->registry;
    }

    public function scan(ScanOptions $options = new ScanOptions()): ScanResult
    {
        $result = new ScanResult();

        foreach ($this->selectChecks($options) as $check) {
            if (! $check->isApplicable()) {
                $result = $result->record($check->id(), CheckStatus::Skipped, [], 'not applicable');
                continue;
            }

            try {
                /** @var array<int, Finding> $findings */
                $findings = [];
                foreach ($check->run() as $f) {
                    $findings[] = $f;
                }

                $status = $findings === [] ? CheckStatus::Passed : CheckStatus::Failed;
                $result = $result->record($check->id(), $status, $findings);
            } catch (Throwable $e) {
                $result = $result->recordError($check->id(), $e);
            }
        }

        return $result;
    }

    /**
     * @return iterable<Check>
     */
    private function selectChecks(ScanOptions $options): iterable
    {
        if ($options->checkPatterns !== []) {
            return $this->registry->matching($options->checkPatterns);
        }

        if ($options->category !== null) {
            return $this->registry->forCategory($options->category);
        }

        return $this->registry->enabled();
    }
}
```

Save as `src/Larascan.php`.

- [ ] **Step 3: Run PHPStan**

```bash
vendor/bin/phpstan analyse --no-progress
```

Expected: OK. (We do not write standalone unit tests for `Larascan` — it's exercised end-to-end via the `ScanCommandTest` in Task 10.)

- [ ] **Step 4: Commit point**

```bash
git add src/Larascan.php src/Support/ScanOptions.php
git commit -m "feat: add Larascan orchestrator and ScanOptions"
```

(**Pause: ask user.**)

---

## Task 10: ServiceProvider + Facade

**Files:**
- Create: `src/LarascanServiceProvider.php`
- Create: `src/Facades/Larascan.php`
- Create: `config/larascan.php`

- [ ] **Step 1: Create `config/larascan.php`**

```php
<?php

declare(strict_types=1);

return [
    'fail_on' => 'high',

    'checks' => [
        // populated as checks are added in later phases
    ],

    'ignore' => [
        'vendor/*',
        'node_modules/*',
        'storage/*',
        'bootstrap/cache/*',
    ],

    'tools' => [
        'semgrep' => env('LARASCAN_SEMGREP_BIN', 'semgrep'),
        'npm' => env('LARASCAN_NPM_BIN', 'npm'),
        'timeout' => 60,
    ],

    'baseline' => null,
];
```

- [ ] **Step 2: Create `LarascanServiceProvider` (minimal — commands and checks are added in later tasks)**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan;

use Baspa\Larascan\Support\CheckRegistry;
use Spatie\LaravelPackageTools\Package;
use Spatie\LaravelPackageTools\PackageServiceProvider;

class LarascanServiceProvider extends PackageServiceProvider
{
    public function configurePackage(Package $package): void
    {
        $package
            ->name('larascan')
            ->hasConfigFile('larascan');
        // hasCommand() calls are appended in Tasks 11, 12, 14.
    }

    public function packageRegistered(): void
    {
        $this->app->singleton(CheckRegistry::class, function (): CheckRegistry {
            /** @var array<string, array{enabled?: bool}> $config */
            $config = $this->app['config']->get('larascan.checks', []);

            $registry = new CheckRegistry($config);

            // Checks shipped with this package are registered in later tasks.

            return $registry;
        });

        $this->app->singleton(Larascan::class, function (): Larascan {
            return new Larascan($this->app->make(CheckRegistry::class));
        });
    }
}
```

Save as `src/LarascanServiceProvider.php`. After this step the provider is autoloadable cleanly; Tasks 11, 12, 13, 14 each modify this file to add their wiring.

- [ ] **Step 3: Create the `Larascan` facade**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Facades;

use Baspa\Larascan\Larascan as LarascanService;
use Baspa\Larascan\Support\ScanOptions;
use Baspa\Larascan\Support\ScanResult;
use Illuminate\Support\Facades\Facade;

/**
 * @method static ScanResult scan(ScanOptions $options = new ScanOptions())
 *
 * @see LarascanService
 */
class Larascan extends Facade
{
    protected static function getFacadeAccessor(): string
    {
        return LarascanService::class;
    }
}
```

Save as `src/Facades/Larascan.php`.

- [ ] **Step 4: Commit point (provider will be exercised in Task 13)**

```bash
git add src/LarascanServiceProvider.php src/Facades/Larascan.php config/larascan.php
git commit -m "feat: wire up ServiceProvider, facade and config skeleton"
```

(**Pause: ask user.**)

---

## Task 11: ScanCommand

**Files:**
- Create: `src/Commands/ScanCommand.php`
- Test: `tests/Feature/ScanCommandTest.php`

- [ ] **Step 1: Write failing test**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Tests\TestCase;

uses(TestCase::class);

it('runs the larascan command and shows the report', function () {
    $this->artisan('larascan')
        ->expectsOutputToContain('larascan — security scan')
        ->expectsOutputToContain('Report')
        ->assertExitCode(0);
});

it('honors --fail-on for exit code', function () {
    // No checks registered yet at this task. The scan runs cleanly and reports
    // no findings → exit 0 regardless of threshold. (After Task 13 the
    // AppDebugCheck is also registered and remains passed in testbench's local env.)
    $this->artisan('larascan --fail-on=critical')->assertExitCode(0);
});

it('filters checks via --check pattern', function () {
    $this->artisan('larascan --check=does.not.exist')
        ->expectsOutputToContain('larascan — security scan')
        ->assertExitCode(0);
});
```

Save as `tests/Feature/ScanCommandTest.php`.

- [ ] **Step 2: Run, see it fail**

```bash
vendor/bin/pest tests/Feature/ScanCommandTest.php
```

Expected: Command `larascan` not found.

- [ ] **Step 3: Implement `ScanCommand`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Commands;

use Baspa\Larascan\Larascan;
use Baspa\Larascan\Reporters\ConsoleReporter;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\ScanOptions;
use Baspa\Larascan\Support\Severity;
use Illuminate\Console\Command;

class ScanCommand extends Command
{
    protected $signature = 'larascan
        {--fail-on= : Severity threshold for non-zero exit code (critical|high|medium|low|info)}
        {--check=* : Filter checks by ID pattern (e.g. cookies.*) — repeatable}
        {--category= : Filter checks by category}
        {--ignore-errors : Force exit 0 even when checks error}';

    protected $description = 'Run larascan security scan';

    public function handle(Larascan $larascan, ConsoleReporter $reporter): int
    {
        $failOnRaw = $this->option('fail-on')
            ?? (string) config('larascan.fail_on', 'high');
        $failOn = Severity::tryFrom((string) $failOnRaw);
        if ($failOn === null) {
            $this->error("Invalid --fail-on value: {$failOnRaw}");
            return 2;
        }

        $categoryRaw = $this->option('category');
        $category = null;
        if (is_string($categoryRaw) && $categoryRaw !== '') {
            $category = Category::tryFrom($categoryRaw);
            if ($category === null) {
                $this->error("Unknown category: {$categoryRaw}");
                return 2;
            }
        }

        /** @var array<int, string> $patterns */
        $patterns = (array) $this->option('check');

        $options = new ScanOptions(
            failOn: $failOn,
            checkPatterns: $patterns,
            category: $category,
        );

        $result = $larascan->scan($options);
        $reporter->render($result, $this->output);

        $counts = $result->counts();
        if ($counts['errored'] > 0 && ! $this->option('ignore-errors')) {
            return 2;
        }

        $highest = $result->highestSeverity();
        if ($highest !== null && $highest->isAtLeast($failOn)) {
            return 1;
        }

        return 0;
    }
}
```

Save as `src/Commands/ScanCommand.php`.

- [ ] **Step 4: Register the command in the service provider**

Edit `src/LarascanServiceProvider.php`. In `configurePackage()`, append `->hasCommand(ScanCommand::class)` to the chain, and add the import at the top:

```php
use Baspa\Larascan\Commands\ScanCommand;
```

Result:
```php
$package
    ->name('larascan')
    ->hasConfigFile('larascan')
    ->hasCommand(ScanCommand::class);
```

- [ ] **Step 5: Run tests + PHPStan**

```bash
vendor/bin/pest tests/Feature/ScanCommandTest.php
vendor/bin/phpstan analyse --no-progress
```

Expected: 3 passed, PHPStan OK. (Note: with no checks registered yet the scan will simply report "Passed: 0, Failed: 0…" — that satisfies the "exit code 0" assertion.)

- [ ] **Step 6: Commit point**

```bash
git add src/Commands/ScanCommand.php tests/Feature/ScanCommandTest.php src/LarascanServiceProvider.php
git commit -m "feat: add ScanCommand artisan command"
```

(**Pause: ask user.**)

---

## Task 12: ListChecksCommand

**Files:**
- Create: `src/Commands/ListChecksCommand.php`
- Test: `tests/Feature/ListChecksCommandTest.php`

- [ ] **Step 1: Write failing test**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Tests\TestCase;

uses(TestCase::class);

it('runs and exits cleanly with no checks registered', function () {
    // At this task no checks are registered yet (AppDebugCheck arrives in Task 13).
    // The table still renders and exit code is 0.
    $this->artisan('larascan:list')->assertExitCode(0);
});

it('accepts a known category filter', function () {
    $this->artisan('larascan:list --category=config')->assertExitCode(0);
});

it('rejects unknown category', function () {
    $this->artisan('larascan:list --category=nope')->assertExitCode(2);
});
```

Save as `tests/Feature/ListChecksCommandTest.php`.

- [ ] **Step 2: Implement `ListChecksCommand`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Commands;

use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\CheckRegistry;
use Illuminate\Console\Command;

class ListChecksCommand extends Command
{
    protected $signature = 'larascan:list
        {--category= : Filter by category}';

    protected $description = 'List all registered larascan checks';

    public function handle(CheckRegistry $registry): int
    {
        $categoryRaw = $this->option('category');
        $category = null;
        if (is_string($categoryRaw) && $categoryRaw !== '') {
            $category = Category::tryFrom($categoryRaw);
            if ($category === null) {
                $this->error("Unknown category: {$categoryRaw}");
                return 2;
            }
        }

        $checks = $category !== null
            ? iterator_to_array($registry->forCategory($category))
            : $registry->all();

        $rows = [];
        foreach ($checks as $check) {
            $rows[] = [
                $check->id(),
                $check->category()->value,
                $check->severity()->value,
                $check->name(),
            ];
        }

        $this->table(['ID', 'Category', 'Severity', 'Name'], $rows);
        return 0;
    }
}
```

Save as `src/Commands/ListChecksCommand.php`.

- [ ] **Step 3: Register the command in the service provider**

Edit `src/LarascanServiceProvider.php`. Add the import at the top:

```php
use Baspa\Larascan\Commands\ListChecksCommand;
```

And append `->hasCommand(ListChecksCommand::class)` to the chain:

```php
$package
    ->name('larascan')
    ->hasConfigFile('larascan')
    ->hasCommand(ScanCommand::class)
    ->hasCommand(ListChecksCommand::class);
```

- [ ] **Step 4: Verify**

```bash
vendor/bin/pest tests/Feature/ListChecksCommandTest.php
vendor/bin/phpstan analyse --no-progress
```

Expected: 3 passed, PHPStan OK.

- [ ] **Step 5: Commit point**

```bash
git add src/Commands/ListChecksCommand.php tests/Feature/ListChecksCommandTest.php src/LarascanServiceProvider.php
git commit -m "feat: add ListChecksCommand artisan command"
```

(**Pause: ask user.**)

---

## Task 13: AppDebugCheck (proof end-to-end)

**Files:**
- Create: `src/Checks/Config/AppDebugCheck.php`
- Test: `tests/Unit/Checks/Config/AppDebugCheckTest.php`

This proves the whole pipeline: a real check, registered by the provider, invoked by the orchestrator, rendered by the reporter.

- [ ] **Step 1: Write failing test**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Config\AppDebugCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Baspa\Larascan\Tests\TestCase;

uses(TestCase::class);

it('exposes correct metadata', function () {
    $check = new AppDebugCheck($this->app);

    expect($check->id())->toBe('config.app-debug')
        ->and($check->category())->toBe(Category::Config)
        ->and($check->severity())->toBe(Severity::Critical);
});

it('is only applicable in production', function () {
    $check = new AppDebugCheck($this->app);

    config()->set('app.env', 'local');
    expect($check->isApplicable())->toBeFalse();

    config()->set('app.env', 'production');
    expect($check->isApplicable())->toBeTrue();
});

it('passes when APP_DEBUG is false in production', function () {
    config()->set('app.env', 'production');
    config()->set('app.debug', false);

    $findings = iterator_to_array((new AppDebugCheck($this->app))->run());
    expect($findings)->toBeEmpty();
});

it('fails when APP_DEBUG is true in production', function () {
    config()->set('app.env', 'production');
    config()->set('app.debug', true);

    $findings = iterator_to_array((new AppDebugCheck($this->app))->run());
    expect($findings)->toHaveCount(1)
        ->and($findings[0]->severity)->toBe(Severity::Critical)
        ->and($findings[0]->checkId)->toBe('config.app-debug');
});
```

Save as `tests/Unit/Checks/Config/AppDebugCheckTest.php`.

- [ ] **Step 2: Run, see it fail**

```bash
vendor/bin/pest tests/Unit/Checks/Config/AppDebugCheckTest.php
```

- [ ] **Step 3: Implement `AppDebugCheck`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Config;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Illuminate\Contracts\Foundation\Application;

final class AppDebugCheck extends AbstractCheck
{
    public function __construct(
        private readonly Application $app,
    ) {
    }

    public function id(): string
    {
        return 'config.app-debug';
    }

    public function category(): Category
    {
        return Category::Config;
    }

    public function severity(): Severity
    {
        return Severity::Critical;
    }

    public function name(): string
    {
        return 'APP_DEBUG must be false in production';
    }

    public function isApplicable(): bool
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make('config');
        return $config->get('app.env') === 'production';
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        /** @var \Illuminate\Contracts\Config\Repository $config */
        $config = $this->app->make('config');

        if ($config->get('app.debug') === true) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severity(),
                message: 'APP_DEBUG is true in production — leaks stack traces and config to attackers.',
            );
        }
    }
}
```

Save as `src/Checks/Config/AppDebugCheck.php`.

- [ ] **Step 4: Register the check in the service provider**

Edit `src/LarascanServiceProvider.php`. Add the import at the top:

```php
use Baspa\Larascan\Checks\Config\AppDebugCheck;
```

In `packageRegistered()`, inside the `CheckRegistry` factory closure, add the registration call:

```php
$this->app->singleton(CheckRegistry::class, function (): CheckRegistry {
    /** @var array<string, array{enabled?: bool}> $config */
    $config = $this->app['config']->get('larascan.checks', []);

    $registry = new CheckRegistry($config);

    $registry->register(new AppDebugCheck($this->app));

    return $registry;
});
```

- [ ] **Step 5: Verify**

```bash
vendor/bin/pest
vendor/bin/phpstan analyse --no-progress
```

Expected: All Pest tests pass, PHPStan clean.

- [ ] **Step 6: Manual smoke test**

```bash
vendor/bin/testbench larascan
vendor/bin/testbench larascan:list
```

Expected: Both commands run cleanly. `larascan:list` shows the `config.app-debug` row.

- [ ] **Step 7: Commit point**

```bash
git add src/Checks tests/Unit/Checks src/LarascanServiceProvider.php
git commit -m "feat: add config.app-debug check (first end-to-end check)"
```

(**Pause: ask user.**)

---

## Task 14: InstallCommand (minimal — publishes config only)

**Files:**
- Create: `src/Commands/InstallCommand.php`
- Test: `tests/Feature/InstallCommandTest.php`

Phase 8 will expand this to publish workflow + semgrep + phpstan stubs and verify external binaries. For now: publish `config/larascan.php` and confirm.

- [ ] **Step 1: Write failing test**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Tests\TestCase;

uses(TestCase::class);

it('publishes the larascan config file', function () {
    $target = config_path('larascan.php');
    if (file_exists($target)) {
        unlink($target);
    }

    $this->artisan('larascan:install --no-interaction')
        ->expectsOutputToContain('Published')
        ->assertExitCode(0);

    expect(file_exists($target))->toBeTrue();
    unlink($target);
});
```

Save as `tests/Feature/InstallCommandTest.php`.

- [ ] **Step 2: Implement `InstallCommand`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Commands;

use Illuminate\Console\Command;

class InstallCommand extends Command
{
    protected $signature = 'larascan:install
        {--no-interaction : Skip prompts}';

    protected $description = 'Publish larascan config and verify environment';

    public function handle(): int
    {
        $this->info('Installing larascan...');

        $this->call('vendor:publish', [
            '--provider' => \Baspa\Larascan\LarascanServiceProvider::class,
            '--tag' => 'larascan-config',
        ]);

        $this->info('Published config/larascan.php');
        $this->newLine();
        $this->line('Next: <comment>php artisan larascan</comment> to run your first scan.');

        return 0;
    }
}
```

Save as `src/Commands/InstallCommand.php`.

(Note: the Spatie `PackageServiceProvider` auto-creates the `larascan-config` publish tag from `hasConfigFile`.)

- [ ] **Step 3: Register the command in the service provider**

Edit `src/LarascanServiceProvider.php`. Add the import:

```php
use Baspa\Larascan\Commands\InstallCommand;
```

Append `->hasCommand(InstallCommand::class)` to the chain:

```php
$package
    ->name('larascan')
    ->hasConfigFile('larascan')
    ->hasCommand(ScanCommand::class)
    ->hasCommand(ListChecksCommand::class)
    ->hasCommand(InstallCommand::class);
```

- [ ] **Step 4: Verify**

```bash
vendor/bin/pest tests/Feature/InstallCommandTest.php
vendor/bin/phpstan analyse --no-progress
```

Expected: 1 passed, PHPStan OK.

- [ ] **Step 5: Commit point**

```bash
git add src/Commands/InstallCommand.php tests/Feature/InstallCommandTest.php src/LarascanServiceProvider.php
git commit -m "feat: add minimal larascan:install command (publishes config)"
```

(**Pause: ask user.**)

---

## Task 15: Replace skeleton CI workflows with our own

**Files:**
- Replace: `.github/workflows/run-tests.yml` → rename to `.github/workflows/tests.yml`
- Replace: `.github/workflows/phpstan.yml`
- Delete: `.github/workflows/dependabot-auto-merge.yml`
- Delete: `.github/workflows/fix-php-code-style-issues.yml`
- Delete: `.github/workflows/update-changelog.yml`

- [ ] **Step 1: Delete skeleton-only workflows**

```bash
rm .github/workflows/dependabot-auto-merge.yml \
   .github/workflows/fix-php-code-style-issues.yml \
   .github/workflows/update-changelog.yml \
   .github/workflows/run-tests.yml
```

- [ ] **Step 2: Create `.github/workflows/tests.yml`**

```yaml
name: tests

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  pest:
    name: Pest (PHP ${{ matrix.php }}, Laravel ${{ matrix.laravel }})
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        php: ['8.2', '8.3', '8.4']
        laravel: ['10.*', '11.*', '12.*', '13.*']
        exclude:
          - { php: '8.2', laravel: '12.*' }
          - { php: '8.2', laravel: '13.*' }

    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: ${{ matrix.php }}
          tools: composer:v2
          coverage: none

      - name: Install dependencies
        run: |
          composer require "illuminate/contracts:${{ matrix.laravel }}" --dev --no-update
          composer update --prefer-dist --no-interaction --no-progress

      - name: Run Pest
        run: vendor/bin/pest
```

- [ ] **Step 3: Rewrite `.github/workflows/phpstan.yml` for level 8**

```yaml
name: phpstan

on:
  pull_request:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  phpstan:
    name: Larastan level 8
    runs-on: ubuntu-latest

    steps:
      - uses: actions/checkout@v4

      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
          tools: composer:v2
          coverage: none

      - name: Install dependencies
        run: composer install --no-interaction --no-progress --prefer-dist

      - name: Run PHPStan
        run: vendor/bin/phpstan analyse --memory-limit=1G --no-progress --error-format=github
```

- [ ] **Step 4: Commit point**

```bash
git add .github/workflows
git commit -m "ci: replace skeleton workflows with tests + phpstan workflows"
```

(**Pause: ask user.**)

---

## Task 16: README

**Files:**
- Replace: `README.md`

- [ ] **Step 1: Replace the skeleton README with a real one**

```markdown
# larascan

Security-focused static analysis for Laravel applications. One artisan command, ~70 checks across config, cookies, headers, auth, models, SQL, XSS, files, injection, crypto, dependencies and more.

> **Status:** Pre-1.0 — Phase 1 (Foundation) complete. See [docs/superpowers/plans](docs/superpowers/plans) for roadmap.

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

## Documentation

- [Design spec](docs/superpowers/specs/2026-05-15-larascan-design.md)
- Per-check documentation lives under `docs/checks/` (added in Phase 7).

## Requirements

- PHP 8.2+
- Laravel 10 / 11 / 12 / 13

## License

MIT
```

- [ ] **Step 2: Commit point**

```bash
git add README.md
git commit -m "docs: replace skeleton README"
```

(**Pause: ask user.**)

---

## Final verification

After every task is complete:

- [ ] **Run the full test suite**

```bash
vendor/bin/pest
```

Expected: All tests pass.

- [ ] **Run PHPStan**

```bash
vendor/bin/phpstan analyse --memory-limit=1G --no-progress
```

Expected: `[OK] No errors`.

- [ ] **Smoke test the CLI**

```bash
vendor/bin/testbench larascan
vendor/bin/testbench larascan:list
vendor/bin/testbench larascan:install --no-interaction
```

Expected: All three commands succeed; `larascan` shows one passed (`config.app-debug`) when `APP_ENV=local`.

- [ ] **Tag this as a checkpoint**

```bash
git tag phase-1-foundation
```

(**Pause: ask user before tagging.**)

---

## Out of scope reminder

Not in this plan:
- Any check other than `config.app-debug`
- Tool wrappers (Semgrep, composer audit, npm audit) — Phase 2
- AST-based checks — Phase 5
- Custom PHPStan rules — Phase 6
- Per-check markdown docs — Phase 7
- Publishable workflow.yml/semgrep.yml/phpstan.neon stubs + full InstallCommand — Phase 8

These come in subsequent plans.
