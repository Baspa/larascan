<?php

declare(strict_types=1);

use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanResult;
use Baspa\Larascan\Support\Severity;

it('records check statuses and findings', function () {
    $result = new ScanResult;
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
    $result = new ScanResult;
    $result = $result->record('x', CheckStatus::Failed, [
        new Finding('x', Severity::Medium, 'a'),
        new Finding('x', Severity::Critical, 'b'),
    ]);

    expect($result->highestSeverity())->toBe(Severity::Critical);
});

it('reports null highest severity when no findings', function () {
    $result = new ScanResult;
    expect($result->highestSeverity())->toBeNull();
});

it('records an errored check with exception class and message', function () {
    $result = new ScanResult;
    $result = $result->recordError('z', new RuntimeException('boom'));

    expect($result->counts()['errored'])->toBe(1)
        ->and($result->errorOf('z'))->toBe('RuntimeException: boom');
});

it('tracks baselined findings per check and in total', function () {
    $result = (new ScanResult)
        ->record('a.check', CheckStatus::Passed, [], null, [
            new Finding('a.check', Severity::High, 'old issue'),
            new Finding('a.check', Severity::High, 'another old issue'),
        ])
        ->record('b.check', CheckStatus::Failed, [
            new Finding('b.check', Severity::Medium, 'new issue'),
        ], null, [
            new Finding('b.check', Severity::Low, 'old issue'),
        ]);

    expect($result->baselinedCount())->toBe(3)
        ->and($result->baselinedCountOf('a.check'))->toBe(2)
        ->and($result->baselinedCountOf('b.check'))->toBe(1)
        ->and($result->baselinedCountOf('c.check'))->toBe(0)
        ->and($result->baselinedFindings())->toHaveCount(3);
});

it('ignores baselined findings for highestSeverity', function () {
    $result = (new ScanResult)
        ->record('a.check', CheckStatus::Failed, [
            new Finding('a.check', Severity::Low, 'new issue'),
        ], null, [
            new Finding('a.check', Severity::Critical, 'old issue'),
        ]);

    expect($result->highestSeverity())->toBe(Severity::Low)
        ->and($result->findings())->toHaveCount(1);
});

it('preserves baselined findings through recordError', function () {
    $result = (new ScanResult)
        ->record('a.check', CheckStatus::Passed, [], null, [
            new Finding('a.check', Severity::High, 'old issue'),
        ])
        ->recordError('z', new RuntimeException('boom'));

    expect($result->baselinedCount())->toBe(1);
});

it('returns a new instance from withStaleBaselineCount', function () {
    $original = (new ScanResult)->record('a.check', CheckStatus::Passed, []);
    $updated = $original->withStaleBaselineCount(3);

    expect($original->staleBaselineCount())->toBe(0)
        ->and($updated->staleBaselineCount())->toBe(3)
        ->and($updated)->not->toBe($original)
        ->and($updated->statusOf('a.check'))->toBe(CheckStatus::Passed);
});
