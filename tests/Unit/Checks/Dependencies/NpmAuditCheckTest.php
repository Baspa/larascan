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
