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
