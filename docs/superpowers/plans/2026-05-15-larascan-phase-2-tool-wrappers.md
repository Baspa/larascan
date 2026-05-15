# Larascan Tool Wrappers — Implementation Plan (Phase 2 of 8)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.
>
> **Commit policy:** Plan-commits per task are authorized. **Never push** without explicit per-instance user permission (`feedback-no-auto-push`). The local repo has `Baspa <hello@baspa.dev>` set; if a subagent's git env lacks it, use `git -c user.name="Baspa" -c user.email="hello@baspa.dev" commit` per-command (no persistent config changes).

**Goal:** Add four external-tool wrappers (`ComposerAuditRunner`, `NpmAuditRunner`, `SemgrepRunner`, `PhpStanRunner`) plus two consumer checks (`dependencies.composer-audit`, `dependencies.npm-audit`) so larascan can shell out to dependency scanners and SAST tools and normalize their output into the existing `Finding` pipeline.

**Architecture:** A `ToolRunner` contract captures the common shape — `isAvailable(): bool` for binary detection. Each runner has two seams: `run()` invokes the binary via `symfony/process` then parses, and `parseOutput(string $json)` is the pure-parse helper that's directly unit-testable. Parsed results flow back as per-tool value objects (`ComposerAdvisory`, `NpmAdvisory`, `SemgrepMatch`, `PhpStanIssue`) which checks then map into the shared `Finding` shape with `Severity::fromCvssScore()` or a string→enum mapping.

**Tech Stack:** PHP 8.2+, `symfony/process ^6.4||^7.0||^8.0`, Pest 4, larastan ^3 at level 8. External binaries: `composer` (always present), `npm`, `semgrep`, `vendor/bin/phpstan`.

**Spec reference:** `docs/superpowers/specs/2026-05-15-larascan-design.md`

**Future plans (NOT in scope here):**
- Phase 3: Config + Cookies + Headers checks (23 checks)
- Phase 4: Auth + CSRF + PHP + Models + Logging + Repo checks (~23 checks)
- Phase 5: AST-based checks (XSS, Files, Injection, Crypto) — many of these will consume `SemgrepRunner`
- Phase 6: Custom PHPStan rules (SQL injection) — will consume `PhpStanRunner`
- Phase 7: Per-check documentation
- Phase 8: Publishable stubs + complete InstallCommand

---

## File map (created/modified in this plan)

**Created:**
- `src/Contracts/ToolRunner.php`
- `src/Tools/ComposerAuditRunner.php`
- `src/Tools/NpmAuditRunner.php`
- `src/Tools/SemgrepRunner.php`
- `src/Tools/PhpStanRunner.php`
- `src/Tools/Output/ComposerAdvisory.php`
- `src/Tools/Output/NpmAdvisory.php`
- `src/Tools/Output/SemgrepMatch.php`
- `src/Tools/Output/PhpStanIssue.php`
- `src/Checks/Dependencies/ComposerAuditCheck.php`
- `src/Checks/Dependencies/NpmAuditCheck.php`
- `tests/Unit/Tools/ComposerAuditRunnerTest.php`
- `tests/Unit/Tools/NpmAuditRunnerTest.php`
- `tests/Unit/Tools/SemgrepRunnerTest.php`
- `tests/Unit/Tools/PhpStanRunnerTest.php`
- `tests/Unit/Checks/Dependencies/ComposerAuditCheckTest.php`
- `tests/Unit/Checks/Dependencies/NpmAuditCheckTest.php`
- `tests/Fixtures/audits/composer-audit-clean.json`
- `tests/Fixtures/audits/composer-audit-vulnerable.json`
- `tests/Fixtures/audits/npm-audit-clean.json`
- `tests/Fixtures/audits/npm-audit-vulnerable.json`
- `tests/Fixtures/audits/semgrep-results.json`
- `tests/Fixtures/audits/phpstan-result.json`

**Modified:**
- `src/LarascanServiceProvider.php` (register two new checks)
- `config/larascan.php` (default enabled state for the two new checks)
- `README.md` (mention the two new checks in usage section)

---

## Task 1: ToolRunner contract + skip-detection helper

**Files:**
- Create: `src/Contracts/ToolRunner.php`
- Test: `tests/Unit/Contracts/ToolRunnerTest.php`

The contract is minimal — runners differ in what they return. The single shared concern is "is this binary installed?" which `isApplicable()` on the consuming `Check` will delegate to.

- [ ] **Step 1: Write a failing test for the contract**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Contracts\ToolRunner;

it('exists as an interface', function () {
    expect(interface_exists(ToolRunner::class))->toBeTrue();
});

it('declares isAvailable returning bool', function () {
    $reflection = new ReflectionClass(ToolRunner::class);
    $method = $reflection->getMethod('isAvailable');
    expect($method->getReturnType()?->__toString())->toBe('bool');
});
```

Save as `tests/Unit/Contracts/ToolRunnerTest.php`.

- [ ] **Step 2: Run, see it fail**

```bash
vendor/bin/pest tests/Unit/Contracts/ToolRunnerTest.php
```

Expected: Interface not found.

- [ ] **Step 3: Implement the contract**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Contracts;

interface ToolRunner
{
    /**
     * Whether the underlying binary/dependency is available on this system.
     *
     * Used by consuming Checks to decide isApplicable().
     */
    public function isAvailable(): bool;
}
```

Save as `src/Contracts/ToolRunner.php`.

- [ ] **Step 4: Verify**

```bash
vendor/bin/pest tests/Unit/Contracts/ToolRunnerTest.php
vendor/bin/phpstan analyse --no-progress
```

Expected: 2 passed, PHPStan OK.

- [ ] **Step 5: Commit**

```bash
git add src/Contracts/ToolRunner.php tests/Unit/Contracts/ToolRunnerTest.php
git commit -m "feat: add ToolRunner contract"
```

---

## Task 2: ComposerAuditRunner + ComposerAdvisory value object

**Files:**
- Create: `src/Tools/Output/ComposerAdvisory.php`
- Create: `src/Tools/ComposerAuditRunner.php`
- Create: `tests/Fixtures/audits/composer-audit-clean.json`
- Create: `tests/Fixtures/audits/composer-audit-vulnerable.json`
- Create: `tests/Unit/Tools/ComposerAuditRunnerTest.php`

The runner shells out to `composer audit --format=json --locked` from the project root, parses the JSON, and yields `ComposerAdvisory` objects. Parsing is exposed as a separate method (`parseOutput`) so tests can feed canned JSON without needing composer installed (composer IS always installed in our CI, but separating parsing keeps the unit fast and deterministic).

- [ ] **Step 1: Create the clean-audit fixture (no advisories)**

Save as `tests/Fixtures/audits/composer-audit-clean.json`:

```json
{
  "advisories": [],
  "abandoned": []
}
```

- [ ] **Step 2: Create the vulnerable-audit fixture (two advisories)**

Save as `tests/Fixtures/audits/composer-audit-vulnerable.json`:

```json
{
  "advisories": {
    "symfony/http-kernel": [
      {
        "advisoryId": "PKSA-1111-1111-1111",
        "packageName": "symfony/http-kernel",
        "affectedVersions": ">=4.0.0,<4.4.50|>=5.0.0,<5.4.20|>=6.0.0,<6.2.6",
        "title": "CVE-2022-24894: HttpKernel: Prevent storing cookie headers in HttpCache",
        "cve": "CVE-2022-24894",
        "link": "https://symfony.com/cve-2022-24894",
        "reportedAt": "2023-02-01T08:00:00+00:00",
        "sources": [{"name": "FriendsOfPHP/security-advisories", "remoteId": "symfony/http-kernel/CVE-2022-24894.yaml"}],
        "severity": "medium",
        "source": "FriendsOfPHP/security-advisories"
      }
    ],
    "guzzlehttp/guzzle": [
      {
        "advisoryId": "PKSA-2222-2222-2222",
        "packageName": "guzzlehttp/guzzle",
        "affectedVersions": "<7.4.5|>=7.5.0,<7.5.1",
        "title": "CVE-2023-29197: Failure to strip authorization header on HTTP downgrade",
        "cve": "CVE-2023-29197",
        "link": "https://github.com/advisories/GHSA-...",
        "reportedAt": "2023-04-17T12:00:00+00:00",
        "sources": [{"name": "GitHub", "remoteId": "GHSA-..."}],
        "severity": "high",
        "source": "GitHub"
      }
    ]
  },
  "abandoned": []
}
```

- [ ] **Step 3: Write failing test for `ComposerAuditRunner`**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Tools\ComposerAuditRunner;
use Baspa\Larascan\Tools\Output\ComposerAdvisory;

it('reports composer is available', function () {
    $runner = new ComposerAuditRunner(workingDir: getcwd() ?: '');
    expect($runner->isAvailable())->toBeTrue();
});

it('parses an empty advisories array as zero advisories', function () {
    $json = (string) file_get_contents(__DIR__ . '/../../Fixtures/audits/composer-audit-clean.json');
    $runner = new ComposerAuditRunner(workingDir: getcwd() ?: '');

    $advisories = iterator_to_array($runner->parseOutput($json));
    expect($advisories)->toBeEmpty();
});

it('parses two advisories from the vulnerable fixture', function () {
    $json = (string) file_get_contents(__DIR__ . '/../../Fixtures/audits/composer-audit-vulnerable.json');
    $runner = new ComposerAuditRunner(workingDir: getcwd() ?: '');

    $advisories = iterator_to_array($runner->parseOutput($json));

    expect($advisories)->toHaveCount(2);

    /** @var ComposerAdvisory $first */
    $first = $advisories[0];
    expect($first)->toBeInstanceOf(ComposerAdvisory::class)
        ->and($first->packageName)->toBe('symfony/http-kernel')
        ->and($first->severity)->toBe('medium')
        ->and($first->cve)->toBe('CVE-2022-24894')
        ->and($first->title)->toContain('HttpKernel');

    /** @var ComposerAdvisory $second */
    $second = $advisories[1];
    expect($second->packageName)->toBe('guzzlehttp/guzzle')
        ->and($second->severity)->toBe('high');
});

it('throws on non-JSON output', function () {
    $runner = new ComposerAuditRunner(workingDir: getcwd() ?: '');
    expect(fn () => iterator_to_array($runner->parseOutput('not json {')))
        ->toThrow(RuntimeException::class, 'Unable to parse composer audit output');
});
```

Save as `tests/Unit/Tools/ComposerAuditRunnerTest.php`.

- [ ] **Step 4: Run, see it fail**

```bash
vendor/bin/pest tests/Unit/Tools/ComposerAuditRunnerTest.php
```

Expected: classes not found.

- [ ] **Step 5: Implement `ComposerAdvisory`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools\Output;

final readonly class ComposerAdvisory
{
    public function __construct(
        public string $packageName,
        public string $title,
        public string $severity,
        public ?string $cve = null,
        public ?string $link = null,
        public ?string $affectedVersions = null,
    ) {
    }
}
```

Save as `src/Tools/Output/ComposerAdvisory.php`.

- [ ] **Step 6: Implement `ComposerAuditRunner`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools;

use Baspa\Larascan\Contracts\ToolRunner;
use Baspa\Larascan\Tools\Output\ComposerAdvisory;
use JsonException;
use RuntimeException;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

class ComposerAuditRunner implements ToolRunner
{
    public function __construct(
        private readonly string $workingDir,
        private readonly string $binary = 'composer',
        private readonly int $timeout = 60,
    ) {
    }

    public function isAvailable(): bool
    {
        return (new ExecutableFinder())->find($this->binary) !== null;
    }

    /**
     * @return iterable<ComposerAdvisory>
     */
    public function run(): iterable
    {
        $process = new Process(
            [$this->binary, 'audit', '--format=json', '--locked', '--no-interaction'],
            $this->workingDir,
        );
        $process->setTimeout((float) $this->timeout);
        $process->run();

        $stdout = $process->getOutput();
        if ($stdout === '') {
            throw new RuntimeException('composer audit produced no output');
        }

        yield from $this->parseOutput($stdout);
    }

    /**
     * @return iterable<ComposerAdvisory>
     */
    public function parseOutput(string $json): iterable
    {
        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Unable to parse composer audit output: ' . $e->getMessage(), previous: $e);
        }

        $advisoriesRaw = $decoded['advisories'] ?? [];
        if (! is_array($advisoriesRaw)) {
            return;
        }

        foreach ($advisoriesRaw as $perPackage) {
            if (! is_array($perPackage)) {
                continue;
            }
            foreach ($perPackage as $entry) {
                if (! is_array($entry)) {
                    continue;
                }
                yield new ComposerAdvisory(
                    packageName: is_string($entry['packageName'] ?? null) ? $entry['packageName'] : '',
                    title: is_string($entry['title'] ?? null) ? $entry['title'] : '',
                    severity: is_string($entry['severity'] ?? null) ? $entry['severity'] : 'medium',
                    cve: is_string($entry['cve'] ?? null) ? $entry['cve'] : null,
                    link: is_string($entry['link'] ?? null) ? $entry['link'] : null,
                    affectedVersions: is_string($entry['affectedVersions'] ?? null) ? $entry['affectedVersions'] : null,
                );
            }
        }
    }
}
```

Save as `src/Tools/ComposerAuditRunner.php`.

- [ ] **Step 7: Verify**

```bash
vendor/bin/pest tests/Unit/Tools/ComposerAuditRunnerTest.php
vendor/bin/phpstan analyse --no-progress
```

Expected: 4 passed, PHPStan OK.

- [ ] **Step 8: Commit**

```bash
git add src/Tools/ComposerAuditRunner.php src/Tools/Output/ComposerAdvisory.php tests/Unit/Tools/ComposerAuditRunnerTest.php tests/Fixtures/audits/composer-audit-clean.json tests/Fixtures/audits/composer-audit-vulnerable.json
git commit -m "feat: add ComposerAuditRunner with advisory parsing"
```

---

## Task 3: ComposerAuditCheck (consumes the runner)

**Files:**
- Create: `src/Checks/Dependencies/ComposerAuditCheck.php`
- Create: `tests/Unit/Checks/Dependencies/ComposerAuditCheckTest.php`
- Modify: `src/LarascanServiceProvider.php` (register the check)
- Modify: `config/larascan.php` (default enabled state)

The check yields one `Finding` per advisory, with severity derived from the advisory's `severity` string (Composer uses `low`/`medium`/`high`).

- [ ] **Step 1: Write failing test**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Dependencies\ComposerAuditCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Baspa\Larascan\Tools\ComposerAuditRunner;
use Baspa\Larascan\Tools\Output\ComposerAdvisory;

final class StubComposerAuditRunner extends ComposerAuditRunner
{
    /** @param array<int, ComposerAdvisory> $advisories */
    public function __construct(
        private readonly array $advisories,
        private readonly bool $available = true,
    ) {
        parent::__construct(workingDir: '');
    }

    public function isAvailable(): bool
    {
        return $this->available;
    }

    /** @return iterable<ComposerAdvisory> */
    public function run(): iterable
    {
        yield from $this->advisories;
    }
}

it('exposes correct metadata', function () {
    $check = new ComposerAuditCheck(new StubComposerAuditRunner([]));

    expect($check->id())->toBe('dependencies.composer-audit')
        ->and($check->category())->toBe(Category::Dependencies)
        ->and($check->severity())->toBe(Severity::High);
});

it('is applicable when the runner reports availability', function () {
    $check = new ComposerAuditCheck(new StubComposerAuditRunner([], available: true));
    expect($check->isApplicable())->toBeTrue();
});

it('is skipped when the runner is not available', function () {
    $check = new ComposerAuditCheck(new StubComposerAuditRunner([], available: false));
    expect($check->isApplicable())->toBeFalse();
});

it('passes when no advisories are returned', function () {
    $check = new ComposerAuditCheck(new StubComposerAuditRunner([]));

    expect(iterator_to_array($check->run()))->toBeEmpty();
});

it('yields one Finding per advisory with severity from the advisory string', function () {
    $advisories = [
        new ComposerAdvisory(
            packageName: 'symfony/http-kernel',
            title: 'CVE-2022-24894 HttpKernel issue',
            severity: 'medium',
            cve: 'CVE-2022-24894',
        ),
        new ComposerAdvisory(
            packageName: 'guzzlehttp/guzzle',
            title: 'CVE-2023-29197 Authorization leak',
            severity: 'high',
        ),
    ];

    $check = new ComposerAuditCheck(new StubComposerAuditRunner($advisories));
    $findings = iterator_to_array($check->run());

    expect($findings)->toHaveCount(2)
        ->and($findings[0]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->message)->toContain('symfony/http-kernel')
        ->and($findings[0]->message)->toContain('CVE-2022-24894')
        ->and($findings[1]->severity)->toBe(Severity::High)
        ->and($findings[1]->message)->toContain('guzzlehttp/guzzle');
});
```

Save as `tests/Unit/Checks/Dependencies/ComposerAuditCheckTest.php`.

- [ ] **Step 2: Run, see it fail**

```bash
vendor/bin/pest tests/Unit/Checks/Dependencies/ComposerAuditCheckTest.php
```

Expected: ComposerAuditCheck not found.

- [ ] **Step 3: Implement `ComposerAuditCheck`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Dependencies;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Baspa\Larascan\Tools\ComposerAuditRunner;

final class ComposerAuditCheck extends AbstractCheck
{
    public function __construct(
        private readonly ComposerAuditRunner $runner,
    ) {
    }

    public function id(): string
    {
        return 'dependencies.composer-audit';
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'composer audit — vulnerable dependencies';
    }

    public function isApplicable(): bool
    {
        return $this->runner->isAvailable();
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        foreach ($this->runner->run() as $advisory) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFromString($advisory->severity),
                message: sprintf(
                    '%s — %s%s',
                    $advisory->packageName,
                    $advisory->title,
                    $advisory->cve !== null ? " ({$advisory->cve})" : '',
                ),
            );
        }
    }

    private function severityFromString(string $value): Severity
    {
        return match (strtolower($value)) {
            'critical' => Severity::Critical,
            'high' => Severity::High,
            'medium', 'moderate' => Severity::Medium,
            'low' => Severity::Low,
            default => Severity::Info,
        };
    }
}
```

Save as `src/Checks/Dependencies/ComposerAuditCheck.php`.

- [ ] **Step 4: Register the check in the service provider**

Edit `src/LarascanServiceProvider.php`. Add the import:

```php
use Baspa\Larascan\Checks\Dependencies\ComposerAuditCheck;
use Baspa\Larascan\Tools\ComposerAuditRunner;
```

Inside `packageRegistered()`'s `CheckRegistry::class` factory, after the existing `AppDebugCheck` registration:

```php
$registry->register(new ComposerAuditCheck(
    new ComposerAuditRunner(workingDir: $this->app->basePath()),
));
```

- [ ] **Step 5: Add the check to default config**

Edit `config/larascan.php`. In the `'checks'` array, add:

```php
'dependencies.composer-audit' => ['enabled' => true],
```

- [ ] **Step 6: Verify**

```bash
vendor/bin/pest tests/Unit/Checks/Dependencies/ComposerAuditCheckTest.php
vendor/bin/pest
vendor/bin/phpstan analyse --no-progress
```

Expected: 5 new tests pass, full suite green, PHPStan clean.

- [ ] **Step 7: Manual smoke test**

```bash
vendor/bin/testbench larascan:list
```

Expected: `dependencies.composer-audit` row appears alongside `config.app-debug`.

- [ ] **Step 8: Commit**

```bash
git add src/Checks/Dependencies/ComposerAuditCheck.php tests/Unit/Checks/Dependencies/ComposerAuditCheckTest.php src/LarascanServiceProvider.php config/larascan.php
git commit -m "feat: add dependencies.composer-audit check"
```

---

## Task 4: NpmAuditRunner + NpmAdvisory value object

**Files:**
- Create: `src/Tools/Output/NpmAdvisory.php`
- Create: `src/Tools/NpmAuditRunner.php`
- Create: `tests/Fixtures/audits/npm-audit-clean.json`
- Create: `tests/Fixtures/audits/npm-audit-vulnerable.json`
- Create: `tests/Unit/Tools/NpmAuditRunnerTest.php`

`npm audit --json` (npm 8+) outputs a `vulnerabilities` object keyed by package name. npm severity vocabulary is `info`/`low`/`moderate`/`high`/`critical`.

- [ ] **Step 1: Create the clean-audit fixture**

Save as `tests/Fixtures/audits/npm-audit-clean.json`:

```json
{
  "auditReportVersion": 2,
  "vulnerabilities": {},
  "metadata": {
    "vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 0, "critical": 0, "total": 0},
    "dependencies": {"prod": 1, "dev": 0, "optional": 0, "peer": 0, "peerOptional": 0, "total": 1}
  }
}
```

- [ ] **Step 2: Create the vulnerable-audit fixture**

Save as `tests/Fixtures/audits/npm-audit-vulnerable.json`:

```json
{
  "auditReportVersion": 2,
  "vulnerabilities": {
    "lodash": {
      "name": "lodash",
      "severity": "high",
      "isDirect": true,
      "via": [{
        "source": 1094499,
        "name": "lodash",
        "dependency": "lodash",
        "title": "Command Injection in lodash",
        "url": "https://github.com/advisories/GHSA-35jh-r3h4-6jhm",
        "severity": "high",
        "cwe": ["CWE-77"],
        "cvss": {"score": 7.2, "vectorString": "CVSS:3.1/..."},
        "range": "<4.17.21"
      }],
      "effects": [],
      "range": "<4.17.21",
      "nodes": ["node_modules/lodash"],
      "fixAvailable": {"name": "lodash", "version": "4.17.21", "isSemVerMajor": false}
    },
    "minimist": {
      "name": "minimist",
      "severity": "critical",
      "isDirect": false,
      "via": [{
        "source": 1096446,
        "name": "minimist",
        "dependency": "minimist",
        "title": "Prototype Pollution in minimist",
        "url": "https://github.com/advisories/GHSA-xvch-5gv4-984h",
        "severity": "critical",
        "cwe": ["CWE-1321"],
        "cvss": {"score": 9.8, "vectorString": "CVSS:3.1/..."},
        "range": "<1.2.6"
      }],
      "effects": [],
      "range": "<1.2.6",
      "nodes": ["node_modules/minimist"],
      "fixAvailable": true
    }
  },
  "metadata": {
    "vulnerabilities": {"info": 0, "low": 0, "moderate": 0, "high": 1, "critical": 1, "total": 2},
    "dependencies": {"prod": 2, "dev": 0, "optional": 0, "peer": 0, "peerOptional": 0, "total": 2}
  }
}
```

- [ ] **Step 3: Write failing test**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Tools\NpmAuditRunner;
use Baspa\Larascan\Tools\Output\NpmAdvisory;

it('parses an empty vulnerabilities object as zero advisories', function () {
    $json = (string) file_get_contents(__DIR__ . '/../../Fixtures/audits/npm-audit-clean.json');
    $runner = new NpmAuditRunner(workingDir: getcwd() ?: '');

    expect(iterator_to_array($runner->parseOutput($json)))->toBeEmpty();
});

it('parses two advisories from the vulnerable fixture', function () {
    $json = (string) file_get_contents(__DIR__ . '/../../Fixtures/audits/npm-audit-vulnerable.json');
    $runner = new NpmAuditRunner(workingDir: getcwd() ?: '');

    $advisories = iterator_to_array($runner->parseOutput($json));

    expect($advisories)->toHaveCount(2);

    /** @var NpmAdvisory $lodash */
    $lodash = $advisories[0];
    expect($lodash)->toBeInstanceOf(NpmAdvisory::class)
        ->and($lodash->packageName)->toBe('lodash')
        ->and($lodash->severity)->toBe('high')
        ->and($lodash->title)->toContain('Command Injection')
        ->and($lodash->range)->toBe('<4.17.21');

    /** @var NpmAdvisory $minimist */
    $minimist = $advisories[1];
    expect($minimist->packageName)->toBe('minimist')
        ->and($minimist->severity)->toBe('critical');
});

it('isAvailable returns false when package.json is missing in workingDir', function () {
    $dir = sys_get_temp_dir() . '/larascan-npm-' . uniqid();
    mkdir($dir);
    try {
        $runner = new NpmAuditRunner(workingDir: $dir);
        expect($runner->isAvailable())->toBeFalse();
    } finally {
        rmdir($dir);
    }
});

it('isAvailable returns true when package.json exists and npm is on PATH', function () {
    $dir = sys_get_temp_dir() . '/larascan-npm-' . uniqid();
    mkdir($dir);
    file_put_contents($dir . '/package.json', '{}');
    try {
        $runner = new NpmAuditRunner(workingDir: $dir);
        if (! (new \Symfony\Component\Process\ExecutableFinder())->find('npm')) {
            $this->markTestSkipped('npm binary not installed');
        }
        expect($runner->isAvailable())->toBeTrue();
    } finally {
        unlink($dir . '/package.json');
        rmdir($dir);
    }
});

it('throws on non-JSON output', function () {
    $runner = new NpmAuditRunner(workingDir: getcwd() ?: '');
    expect(fn () => iterator_to_array($runner->parseOutput('garbage')))
        ->toThrow(RuntimeException::class, 'Unable to parse npm audit output');
});
```

Save as `tests/Unit/Tools/NpmAuditRunnerTest.php`.

- [ ] **Step 4: Run, see it fail**

```bash
vendor/bin/pest tests/Unit/Tools/NpmAuditRunnerTest.php
```

- [ ] **Step 5: Implement `NpmAdvisory`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools\Output;

final readonly class NpmAdvisory
{
    public function __construct(
        public string $packageName,
        public string $title,
        public string $severity,
        public ?string $range = null,
        public ?string $url = null,
    ) {
    }
}
```

Save as `src/Tools/Output/NpmAdvisory.php`.

- [ ] **Step 6: Implement `NpmAuditRunner`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools;

use Baspa\Larascan\Contracts\ToolRunner;
use Baspa\Larascan\Tools\Output\NpmAdvisory;
use JsonException;
use RuntimeException;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

class NpmAuditRunner implements ToolRunner
{
    public function __construct(
        private readonly string $workingDir,
        private readonly string $binary = 'npm',
        private readonly int $timeout = 120,
    ) {
    }

    public function isAvailable(): bool
    {
        if (! is_file($this->workingDir . '/package.json')) {
            return false;
        }
        return (new ExecutableFinder())->find($this->binary) !== null;
    }

    /**
     * @return iterable<NpmAdvisory>
     */
    public function run(): iterable
    {
        $process = new Process([$this->binary, 'audit', '--json'], $this->workingDir);
        $process->setTimeout((float) $this->timeout);
        $process->run();

        $stdout = $process->getOutput();
        if ($stdout === '') {
            throw new RuntimeException('npm audit produced no output');
        }

        yield from $this->parseOutput($stdout);
    }

    /**
     * @return iterable<NpmAdvisory>
     */
    public function parseOutput(string $json): iterable
    {
        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Unable to parse npm audit output: ' . $e->getMessage(), previous: $e);
        }

        $vulns = $decoded['vulnerabilities'] ?? [];
        if (! is_array($vulns)) {
            return;
        }

        foreach ($vulns as $name => $entry) {
            if (! is_array($entry) || ! is_string($name)) {
                continue;
            }

            $title = '';
            $url = null;
            $viaList = $entry['via'] ?? [];
            if (is_array($viaList)) {
                foreach ($viaList as $via) {
                    if (is_array($via) && is_string($via['title'] ?? null)) {
                        $title = $via['title'];
                        $url = is_string($via['url'] ?? null) ? $via['url'] : null;
                        break;
                    }
                }
            }

            yield new NpmAdvisory(
                packageName: $name,
                title: $title !== '' ? $title : "Vulnerability in {$name}",
                severity: is_string($entry['severity'] ?? null) ? $entry['severity'] : 'low',
                range: is_string($entry['range'] ?? null) ? $entry['range'] : null,
                url: $url,
            );
        }
    }
}
```

Save as `src/Tools/NpmAuditRunner.php`.

- [ ] **Step 7: Verify**

```bash
vendor/bin/pest tests/Unit/Tools/NpmAuditRunnerTest.php
vendor/bin/phpstan analyse --no-progress
```

Expected: 5 passed, PHPStan OK.

- [ ] **Step 8: Commit**

```bash
git add src/Tools/NpmAuditRunner.php src/Tools/Output/NpmAdvisory.php tests/Unit/Tools/NpmAuditRunnerTest.php tests/Fixtures/audits/npm-audit-clean.json tests/Fixtures/audits/npm-audit-vulnerable.json
git commit -m "feat: add NpmAuditRunner with advisory parsing"
```

---

## Task 5: NpmAuditCheck (consumes the runner)

**Files:**
- Create: `src/Checks/Dependencies/NpmAuditCheck.php`
- Create: `tests/Unit/Checks/Dependencies/NpmAuditCheckTest.php`
- Modify: `src/LarascanServiceProvider.php` (register the check)
- Modify: `config/larascan.php` (default enabled state)

- [ ] **Step 1: Write failing test**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Checks\Dependencies\NpmAuditCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Severity;
use Baspa\Larascan\Tools\NpmAuditRunner;
use Baspa\Larascan\Tools\Output\NpmAdvisory;

final class StubNpmAuditRunner extends NpmAuditRunner
{
    /** @param array<int, NpmAdvisory> $advisories */
    public function __construct(
        private readonly array $advisories,
        private readonly bool $available = true,
    ) {
        parent::__construct(workingDir: '');
    }

    public function isAvailable(): bool
    {
        return $this->available;
    }

    /** @return iterable<NpmAdvisory> */
    public function run(): iterable
    {
        yield from $this->advisories;
    }
}

it('exposes correct metadata', function () {
    $check = new NpmAuditCheck(new StubNpmAuditRunner([]));

    expect($check->id())->toBe('dependencies.npm-audit')
        ->and($check->category())->toBe(Category::Dependencies)
        ->and($check->severity())->toBe(Severity::High);
});

it('is skipped when no package.json (runner not available)', function () {
    $check = new NpmAuditCheck(new StubNpmAuditRunner([], available: false));
    expect($check->isApplicable())->toBeFalse();
});

it('passes when no advisories', function () {
    $check = new NpmAuditCheck(new StubNpmAuditRunner([]));
    expect(iterator_to_array($check->run()))->toBeEmpty();
});

it('maps npm severity vocabulary including critical and moderate', function () {
    $advisories = [
        new NpmAdvisory('lodash', 'Command Injection in lodash', 'high', '<4.17.21'),
        new NpmAdvisory('minimist', 'Prototype Pollution in minimist', 'critical', '<1.2.6'),
        new NpmAdvisory('semver', 'ReDoS in semver', 'moderate', '<7.5.2'),
    ];

    $check = new NpmAuditCheck(new StubNpmAuditRunner($advisories));
    $findings = iterator_to_array($check->run());

    expect($findings)->toHaveCount(3)
        ->and($findings[0]->severity)->toBe(Severity::High)
        ->and($findings[1]->severity)->toBe(Severity::Critical)
        ->and($findings[2]->severity)->toBe(Severity::Medium)
        ->and($findings[0]->message)->toContain('lodash')
        ->and($findings[1]->message)->toContain('minimist');
});
```

Save as `tests/Unit/Checks/Dependencies/NpmAuditCheckTest.php`.

- [ ] **Step 2: Run, see it fail**

```bash
vendor/bin/pest tests/Unit/Checks/Dependencies/NpmAuditCheckTest.php
```

- [ ] **Step 3: Implement `NpmAuditCheck`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Checks\Dependencies;

use Baspa\Larascan\Support\AbstractCheck;
use Baspa\Larascan\Support\Category;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\Severity;
use Baspa\Larascan\Tools\NpmAuditRunner;

final class NpmAuditCheck extends AbstractCheck
{
    public function __construct(
        private readonly NpmAuditRunner $runner,
    ) {
    }

    public function id(): string
    {
        return 'dependencies.npm-audit';
    }

    public function category(): Category
    {
        return Category::Dependencies;
    }

    public function severity(): Severity
    {
        return Severity::High;
    }

    public function name(): string
    {
        return 'npm audit — vulnerable JS dependencies';
    }

    public function isApplicable(): bool
    {
        return $this->runner->isAvailable();
    }

    /**
     * @return iterable<Finding>
     */
    public function run(): iterable
    {
        foreach ($this->runner->run() as $advisory) {
            yield new Finding(
                checkId: $this->id(),
                severity: $this->severityFromString($advisory->severity),
                message: sprintf(
                    '%s%s — %s',
                    $advisory->packageName,
                    $advisory->range !== null ? " {$advisory->range}" : '',
                    $advisory->title,
                ),
            );
        }
    }

    private function severityFromString(string $value): Severity
    {
        return match (strtolower($value)) {
            'critical' => Severity::Critical,
            'high' => Severity::High,
            'moderate', 'medium' => Severity::Medium,
            'low' => Severity::Low,
            default => Severity::Info,
        };
    }
}
```

Save as `src/Checks/Dependencies/NpmAuditCheck.php`.

- [ ] **Step 4: Register in service provider**

Edit `src/LarascanServiceProvider.php`. Add imports:

```php
use Baspa\Larascan\Checks\Dependencies\NpmAuditCheck;
use Baspa\Larascan\Tools\NpmAuditRunner;
```

In the `CheckRegistry::class` factory (after the ComposerAuditCheck registration):

```php
$registry->register(new NpmAuditCheck(
    new NpmAuditRunner(workingDir: $this->app->basePath()),
));
```

- [ ] **Step 5: Add to default config**

Edit `config/larascan.php`. In the `'checks'` array:

```php
'dependencies.npm-audit' => ['enabled' => true],
```

- [ ] **Step 6: Verify**

```bash
vendor/bin/pest tests/Unit/Checks/Dependencies/NpmAuditCheckTest.php
vendor/bin/pest
vendor/bin/phpstan analyse --no-progress
```

Expected: 4 new tests pass, full suite green, PHPStan clean.

- [ ] **Step 7: Manual smoke test**

```bash
vendor/bin/testbench larascan:list
```

Expected: `dependencies.npm-audit` row appears.

- [ ] **Step 8: Commit**

```bash
git add src/Checks/Dependencies/NpmAuditCheck.php tests/Unit/Checks/Dependencies/NpmAuditCheckTest.php src/LarascanServiceProvider.php config/larascan.php
git commit -m "feat: add dependencies.npm-audit check"
```

---

## Task 6: SemgrepRunner + SemgrepMatch value object

**Files:**
- Create: `src/Tools/Output/SemgrepMatch.php`
- Create: `src/Tools/SemgrepRunner.php`
- Create: `tests/Fixtures/audits/semgrep-results.json`
- Create: `tests/Unit/Tools/SemgrepRunnerTest.php`

No consumer check in this phase — Phase 5 SAST checks will inject a `SemgrepRunner` configured with their specific rule sets.

- [ ] **Step 1: Create the semgrep results fixture**

Save as `tests/Fixtures/audits/semgrep-results.json`:

```json
{
  "version": "1.50.0",
  "results": [
    {
      "check_id": "larascan.blade-unescaped-request",
      "path": "resources/views/profile.blade.php",
      "start": {"line": 14, "col": 1, "offset": 220},
      "end": {"line": 14, "col": 42, "offset": 261},
      "extra": {
        "message": "Unescaped Blade variable {!! $request->name !!} — likely XSS",
        "severity": "ERROR",
        "metadata": {"category": "security"}
      }
    },
    {
      "check_id": "larascan.dd-in-production",
      "path": "app/Http/Controllers/UserController.php",
      "start": {"line": 42, "col": 9, "offset": 1024},
      "end": {"line": 42, "col": 22, "offset": 1037},
      "extra": {
        "message": "dd() call left in code",
        "severity": "WARNING",
        "metadata": {}
      }
    }
  ],
  "errors": [],
  "paths": {"scanned": ["app", "resources"]}
}
```

- [ ] **Step 2: Write failing test**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Tools\Output\SemgrepMatch;
use Baspa\Larascan\Tools\SemgrepRunner;

it('parses zero matches from an empty results array', function () {
    $runner = new SemgrepRunner(workingDir: getcwd() ?: '');
    $matches = iterator_to_array($runner->parseOutput('{"version":"1.0","results":[],"errors":[]}'));

    expect($matches)->toBeEmpty();
});

it('parses two matches from the fixture', function () {
    $json = (string) file_get_contents(__DIR__ . '/../../Fixtures/audits/semgrep-results.json');
    $runner = new SemgrepRunner(workingDir: getcwd() ?: '');

    $matches = iterator_to_array($runner->parseOutput($json));

    expect($matches)->toHaveCount(2);

    /** @var SemgrepMatch $first */
    $first = $matches[0];
    expect($first)->toBeInstanceOf(SemgrepMatch::class)
        ->and($first->checkId)->toBe('larascan.blade-unescaped-request')
        ->and($first->path)->toBe('resources/views/profile.blade.php')
        ->and($first->line)->toBe(14)
        ->and($first->severity)->toBe('ERROR')
        ->and($first->message)->toContain('XSS');

    /** @var SemgrepMatch $second */
    $second = $matches[1];
    expect($second->checkId)->toBe('larascan.dd-in-production')
        ->and($second->path)->toBe('app/Http/Controllers/UserController.php')
        ->and($second->line)->toBe(42)
        ->and($second->severity)->toBe('WARNING');
});

it('isAvailable depends on the semgrep binary being on PATH', function () {
    $runner = new SemgrepRunner(workingDir: getcwd() ?: '');
    $finder = new \Symfony\Component\Process\ExecutableFinder();
    expect($runner->isAvailable())->toBe($finder->find('semgrep') !== null);
});

it('throws on non-JSON output', function () {
    $runner = new SemgrepRunner(workingDir: getcwd() ?: '');
    expect(fn () => iterator_to_array($runner->parseOutput('not json')))
        ->toThrow(RuntimeException::class, 'Unable to parse semgrep output');
});
```

Save as `tests/Unit/Tools/SemgrepRunnerTest.php`.

- [ ] **Step 3: Implement `SemgrepMatch`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools\Output;

final readonly class SemgrepMatch
{
    public function __construct(
        public string $checkId,
        public string $path,
        public int $line,
        public string $severity,
        public string $message,
    ) {
    }
}
```

Save as `src/Tools/Output/SemgrepMatch.php`.

- [ ] **Step 4: Implement `SemgrepRunner`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools;

use Baspa\Larascan\Contracts\ToolRunner;
use Baspa\Larascan\Tools\Output\SemgrepMatch;
use JsonException;
use RuntimeException;
use Symfony\Component\Process\ExecutableFinder;
use Symfony\Component\Process\Process;

class SemgrepRunner implements ToolRunner
{
    /**
     * @param array<int, string> $configs  paths or registry URLs passed to --config
     * @param array<int, string> $targets  paths to scan; defaults to workingDir if empty
     */
    public function __construct(
        private readonly string $workingDir,
        private readonly array $configs = [],
        private readonly array $targets = [],
        private readonly string $binary = 'semgrep',
        private readonly int $timeout = 300,
    ) {
    }

    public function isAvailable(): bool
    {
        return (new ExecutableFinder())->find($this->binary) !== null;
    }

    /**
     * @return iterable<SemgrepMatch>
     */
    public function run(): iterable
    {
        $command = [$this->binary, '--json', '--quiet'];
        foreach ($this->configs as $config) {
            $command[] = '--config';
            $command[] = $config;
        }
        $command = array_merge($command, $this->targets !== [] ? $this->targets : ['.']);

        $process = new Process($command, $this->workingDir);
        $process->setTimeout((float) $this->timeout);
        $process->run();

        $stdout = $process->getOutput();
        if ($stdout === '') {
            throw new RuntimeException('semgrep produced no output');
        }

        yield from $this->parseOutput($stdout);
    }

    /**
     * @return iterable<SemgrepMatch>
     */
    public function parseOutput(string $json): iterable
    {
        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Unable to parse semgrep output: ' . $e->getMessage(), previous: $e);
        }

        $results = $decoded['results'] ?? [];
        if (! is_array($results)) {
            return;
        }

        foreach ($results as $entry) {
            if (! is_array($entry)) {
                continue;
            }
            $extra = $entry['extra'] ?? [];
            $start = $entry['start'] ?? [];
            $line = is_array($start) && is_int($start['line'] ?? null) ? $start['line'] : 0;

            yield new SemgrepMatch(
                checkId: is_string($entry['check_id'] ?? null) ? $entry['check_id'] : '',
                path: is_string($entry['path'] ?? null) ? $entry['path'] : '',
                line: $line,
                severity: is_array($extra) && is_string($extra['severity'] ?? null) ? $extra['severity'] : 'INFO',
                message: is_array($extra) && is_string($extra['message'] ?? null) ? $extra['message'] : '',
            );
        }
    }
}
```

Save as `src/Tools/SemgrepRunner.php`.

- [ ] **Step 5: Verify**

```bash
vendor/bin/pest tests/Unit/Tools/SemgrepRunnerTest.php
vendor/bin/phpstan analyse --no-progress
```

Expected: 4 passed, PHPStan OK.

- [ ] **Step 6: Commit**

```bash
git add src/Tools/SemgrepRunner.php src/Tools/Output/SemgrepMatch.php tests/Unit/Tools/SemgrepRunnerTest.php tests/Fixtures/audits/semgrep-results.json
git commit -m "feat: add SemgrepRunner for SAST integration"
```

---

## Task 7: PhpStanRunner + PhpStanIssue value object

**Files:**
- Create: `src/Tools/Output/PhpStanIssue.php`
- Create: `src/Tools/PhpStanRunner.php`
- Create: `tests/Fixtures/audits/phpstan-result.json`
- Create: `tests/Unit/Tools/PhpStanRunnerTest.php`

No consumer check in this phase. Phase 6 will use this runner with custom rules to back the SQL-injection check group.

- [ ] **Step 1: Create the PHPStan results fixture**

Save as `tests/Fixtures/audits/phpstan-result.json`:

```json
{
  "totals": {"errors": 0, "file_errors": 2},
  "files": {
    "/app/app/Http/Controllers/UserController.php": {
      "errors": 1,
      "messages": [
        {
          "message": "Raw SQL query receives user input — possible SQL injection",
          "line": 42,
          "ignorable": false,
          "identifier": "larascan.rawQueryUserInput"
        }
      ]
    },
    "/app/app/Models/User.php": {
      "errors": 1,
      "messages": [
        {
          "message": "Unguarded model — possible mass assignment",
          "line": 12,
          "ignorable": true,
          "identifier": "larascan.unguardedModel"
        }
      ]
    }
  },
  "errors": []
}
```

- [ ] **Step 2: Write failing test**

```php
<?php

declare(strict_types=1);

use Baspa\Larascan\Tools\Output\PhpStanIssue;
use Baspa\Larascan\Tools\PhpStanRunner;

it('parses zero issues from an empty files object', function () {
    $runner = new PhpStanRunner(workingDir: getcwd() ?: '');
    expect(iterator_to_array($runner->parseOutput('{"totals":{"errors":0,"file_errors":0},"files":{},"errors":[]}')))->toBeEmpty();
});

it('parses two issues from the fixture across two files', function () {
    $json = (string) file_get_contents(__DIR__ . '/../../Fixtures/audits/phpstan-result.json');
    $runner = new PhpStanRunner(workingDir: getcwd() ?: '');

    $issues = iterator_to_array($runner->parseOutput($json));

    expect($issues)->toHaveCount(2);

    /** @var PhpStanIssue $first */
    $first = $issues[0];
    expect($first)->toBeInstanceOf(PhpStanIssue::class)
        ->and($first->file)->toBe('/app/app/Http/Controllers/UserController.php')
        ->and($first->line)->toBe(42)
        ->and($first->identifier)->toBe('larascan.rawQueryUserInput')
        ->and($first->message)->toContain('SQL injection');

    /** @var PhpStanIssue $second */
    $second = $issues[1];
    expect($second->file)->toBe('/app/app/Models/User.php')
        ->and($second->identifier)->toBe('larascan.unguardedModel');
});

it('isAvailable returns true when vendor/bin/phpstan exists in workingDir', function () {
    $dir = sys_get_temp_dir() . '/larascan-phpstan-' . uniqid();
    mkdir($dir . '/vendor/bin', recursive: true);
    file_put_contents($dir . '/vendor/bin/phpstan', '#!/bin/sh');
    chmod($dir . '/vendor/bin/phpstan', 0755);
    try {
        $runner = new PhpStanRunner(workingDir: $dir);
        expect($runner->isAvailable())->toBeTrue();
    } finally {
        unlink($dir . '/vendor/bin/phpstan');
        rmdir($dir . '/vendor/bin');
        rmdir($dir . '/vendor');
        rmdir($dir);
    }
});

it('isAvailable returns false when vendor/bin/phpstan is absent', function () {
    $dir = sys_get_temp_dir() . '/larascan-phpstan-' . uniqid();
    mkdir($dir);
    try {
        $runner = new PhpStanRunner(workingDir: $dir);
        expect($runner->isAvailable())->toBeFalse();
    } finally {
        rmdir($dir);
    }
});

it('throws on non-JSON output', function () {
    $runner = new PhpStanRunner(workingDir: getcwd() ?: '');
    expect(fn () => iterator_to_array($runner->parseOutput('garbage')))
        ->toThrow(RuntimeException::class, 'Unable to parse phpstan output');
});
```

Save as `tests/Unit/Tools/PhpStanRunnerTest.php`.

- [ ] **Step 3: Implement `PhpStanIssue`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools\Output;

final readonly class PhpStanIssue
{
    public function __construct(
        public string $file,
        public int $line,
        public string $message,
        public ?string $identifier = null,
        public bool $ignorable = false,
    ) {
    }
}
```

Save as `src/Tools/Output/PhpStanIssue.php`.

- [ ] **Step 4: Implement `PhpStanRunner`**

```php
<?php

declare(strict_types=1);

namespace Baspa\Larascan\Tools;

use Baspa\Larascan\Contracts\ToolRunner;
use Baspa\Larascan\Tools\Output\PhpStanIssue;
use JsonException;
use RuntimeException;
use Symfony\Component\Process\Process;

class PhpStanRunner implements ToolRunner
{
    /**
     * @param array<int, string> $paths
     */
    public function __construct(
        private readonly string $workingDir,
        private readonly ?string $configFile = null,
        private readonly array $paths = [],
        private readonly int $timeout = 300,
    ) {
    }

    public function isAvailable(): bool
    {
        return is_file($this->workingDir . '/vendor/bin/phpstan');
    }

    /**
     * @return iterable<PhpStanIssue>
     */
    public function run(): iterable
    {
        $binary = $this->workingDir . '/vendor/bin/phpstan';
        $command = [$binary, 'analyse', '--error-format=json', '--no-progress'];
        if ($this->configFile !== null) {
            $command[] = '--configuration';
            $command[] = $this->configFile;
        }
        $command = array_merge($command, $this->paths);

        $process = new Process($command, $this->workingDir);
        $process->setTimeout((float) $this->timeout);
        $process->run();

        $stdout = $process->getOutput();
        if ($stdout === '') {
            throw new RuntimeException('phpstan produced no output');
        }

        yield from $this->parseOutput($stdout);
    }

    /**
     * @return iterable<PhpStanIssue>
     */
    public function parseOutput(string $json): iterable
    {
        try {
            /** @var array<string, mixed> $decoded */
            $decoded = json_decode($json, associative: true, flags: JSON_THROW_ON_ERROR);
        } catch (JsonException $e) {
            throw new RuntimeException('Unable to parse phpstan output: ' . $e->getMessage(), previous: $e);
        }

        $files = $decoded['files'] ?? [];
        if (! is_array($files)) {
            return;
        }

        foreach ($files as $path => $fileEntry) {
            if (! is_array($fileEntry) || ! is_string($path)) {
                continue;
            }
            $messages = $fileEntry['messages'] ?? [];
            if (! is_array($messages)) {
                continue;
            }
            foreach ($messages as $msg) {
                if (! is_array($msg)) {
                    continue;
                }
                yield new PhpStanIssue(
                    file: $path,
                    line: is_int($msg['line'] ?? null) ? $msg['line'] : 0,
                    message: is_string($msg['message'] ?? null) ? $msg['message'] : '',
                    identifier: is_string($msg['identifier'] ?? null) ? $msg['identifier'] : null,
                    ignorable: (bool) ($msg['ignorable'] ?? false),
                );
            }
        }
    }
}
```

Save as `src/Tools/PhpStanRunner.php`.

- [ ] **Step 5: Verify**

```bash
vendor/bin/pest tests/Unit/Tools/PhpStanRunnerTest.php
vendor/bin/phpstan analyse --no-progress
```

Expected: 5 passed, PHPStan OK.

- [ ] **Step 6: Commit**

```bash
git add src/Tools/PhpStanRunner.php src/Tools/Output/PhpStanIssue.php tests/Unit/Tools/PhpStanRunnerTest.php tests/Fixtures/audits/phpstan-result.json
git commit -m "feat: add PhpStanRunner for static analysis integration"
```

---

## Task 8: README update + final verification

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Update the README usage block to mention the new checks**

Find the section between `## Usage` and the next `##`. Append two lines after the existing usage examples so the section reads:

```markdown
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
```

Also update the `> **Status:**` line:

```markdown
> **Status:** Pre-1.0 — Phase 2 (Tool wrappers) complete. See [docs/superpowers/plans](docs/superpowers/plans) for roadmap.
```

- [ ] **Step 2: Full verification pass**

```bash
vendor/bin/pest --compact
vendor/bin/phpstan analyse --memory-limit=1G --no-progress
vendor/bin/pint --test
```

Expected:
- Pest: ~62 tests passing (39 from Phase 1 + ~23 new)
- PHPStan: `[OK] No errors`
- Pint: no style violations

- [ ] **Step 3: Manual smoke test**

```bash
vendor/bin/testbench larascan:list
```

Expected: 3 rows — `config.app-debug`, `dependencies.composer-audit`, `dependencies.npm-audit`.

```bash
vendor/bin/testbench larascan
```

Expected: Composer audit runs against the package's own composer.lock and either passes or reports advisories. The npm-audit check is skipped (no package.json in the package itself).

- [ ] **Step 4: Commit**

```bash
git add README.md
git commit -m "docs: update README for Phase 2 tool wrappers"
```

---

## Final verification

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

- [ ] **Run Pint test mode**

```bash
vendor/bin/pint --test
```

Expected: No style violations. If any appear, run `vendor/bin/pint` and add a follow-up commit `style: apply Pint formatting`.

- [ ] **Smoke test the new checks**

```bash
vendor/bin/testbench larascan:list
vendor/bin/testbench larascan --category=dependencies
```

Expected: Composer audit runs; npm audit shows as skipped if no package.json. Exit code reflects findings.

---

## Out of scope reminder

Not in this plan:
- Custom Semgrep ruleset (`resources/stubs/semgrep.yml`) — Phase 8
- Custom PHPStan rules used by Semgrep/PhpStan runners — Phase 6
- Any check beyond `dependencies.composer-audit` and `dependencies.npm-audit` — Phases 3, 4, 5, 6
- Per-check markdown documentation — Phase 7
- SARIF output, baseline file support — Phase 8+ (out of v1 spec entirely for v1)
