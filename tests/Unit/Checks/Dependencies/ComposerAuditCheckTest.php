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
