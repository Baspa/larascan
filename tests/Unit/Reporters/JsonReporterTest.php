<?php

declare(strict_types=1);

use Baspa\Larascan\Reporters\JsonReporter;
use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanResult;
use Baspa\Larascan\Support\Severity;
use Symfony\Component\Console\Output\BufferedOutput;

it('renders valid JSON with summary and checks', function () {
    $result = (new ScanResult)
        ->record('config.app-debug', CheckStatus::Passed, [])
        ->record('cookies.session-secure', CheckStatus::Failed, [
            new Finding('cookies.session-secure', Severity::Critical, 'SESSION_SECURE_COOKIE is false'),
        ])
        ->record('dependencies.npm-audit', CheckStatus::Skipped, [], 'no package.json');

    $output = new BufferedOutput;
    (new JsonReporter)->render($result, $output);

    $decoded = json_decode($output->fetch(), true);

    expect($decoded)->toBeArray()
        ->and($decoded['version'])->toBe('1.0')
        ->and($decoded['summary']['passed'])->toBe(1)
        ->and($decoded['summary']['failed'])->toBe(1)
        ->and($decoded['summary']['skipped'])->toBe(1)
        ->and($decoded['summary']['highest_severity'])->toBe('critical')
        ->and($decoded['checks'])->toHaveCount(3);
});

it('includes file and line in findings when present', function () {
    $result = (new ScanResult)
        ->record('sql.raw-user-input', CheckStatus::Failed, [
            new Finding(
                checkId: 'sql.raw-user-input',
                severity: Severity::Critical,
                message: 'Raw SQL',
                file: 'app/Foo.php',
                line: 42,
            ),
        ]);

    $output = new BufferedOutput;
    (new JsonReporter)->render($result, $output);

    $decoded = json_decode($output->fetch(), true);
    $sqlFinding = $decoded['checks'][0]['findings'][0];
    expect($sqlFinding['file'])->toBe('app/Foo.php')
        ->and($sqlFinding['line'])->toBe(42);
});

it('filters checks array when onlyFailed is true but keeps summary intact', function () {
    $result = (new ScanResult)
        ->record('config.app-debug', CheckStatus::Passed, [])
        ->record('config.app-env', CheckStatus::Failed, [
            new Finding('config.app-env', Severity::Info, 'APP_ENV is dev'),
        ])
        ->record('dependencies.npm-audit', CheckStatus::Skipped, [], 'no package.json');

    $output = new BufferedOutput;
    (new JsonReporter)->render($result, $output, onlyFailed: true);
    $decoded = json_decode($output->fetch(), true);

    expect($decoded['checks'])->toHaveCount(1)
        ->and($decoded['checks'][0]['id'])->toBe('config.app-env')
        ->and($decoded['summary']['passed'])->toBe(1)
        ->and($decoded['summary']['failed'])->toBe(1)
        ->and($decoded['summary']['skipped'])->toBe(1);
});

it('includes skip_reason for skipped checks', function () {
    $result = (new ScanResult)
        ->record('dependencies.npm-audit', CheckStatus::Skipped, [], 'no package.json');

    $output = new BufferedOutput;
    (new JsonReporter)->render($result, $output);

    $decoded = json_decode($output->fetch(), true);
    expect($decoded['checks'][0]['skip_reason'])->toBe('no package.json');
});
