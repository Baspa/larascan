<?php

declare(strict_types=1);

use Baspa\Larascan\Reporters\ConsoleReporter;
use Baspa\Larascan\Support\CheckStatus;
use Baspa\Larascan\Support\Finding;
use Baspa\Larascan\Support\ScanResult;
use Baspa\Larascan\Support\Severity;
use Symfony\Component\Console\Output\BufferedOutput;

it('renders a passed, failed and skipped row plus summary', function () {
    $result = (new ScanResult)
        ->record('config.app-debug', CheckStatus::Passed, [])
        ->record('cookies.session-secure', CheckStatus::Failed, [
            new Finding('cookies.session-secure', Severity::Critical, 'SESSION_SECURE_COOKIE is false'),
        ])
        ->record('dependencies.npm-audit', CheckStatus::Skipped, [], 'no package.json');

    $output = new BufferedOutput;
    (new ConsoleReporter)->render($result, $output);

    $text = $output->fetch();
    expect($text)
        ->toContain('config.app-debug')
        ->toContain('cookies.session-secure')
        ->toContain('CRITICAL')
        ->toContain('SESSION_SECURE_COOKIE is false')
        ->toContain('dependencies.npm-audit')
        ->toContain('skipped — no package.json')
        ->toContain('1 passed')
        ->toContain('1 failed')
        ->toContain('1 skipped');
});

it('renders human output with check ids visible', function () {
    $result = (new ScanResult)
        ->record('config.app-debug', CheckStatus::Passed, [])
        ->record('cookies.session-secure', CheckStatus::Failed, [
            new Finding('cookies.session-secure', Severity::Critical, 'SESSION_SECURE_COOKIE is false'),
        ]);

    $output = new BufferedOutput;
    (new ConsoleReporter)->render($result, $output);

    $text = $output->fetch();
    expect($text)
        ->toContain('config.app-debug')
        ->toContain('cookies.session-secure')
        ->toContain('CRITICAL');
});

it('groups findings under a single check header and shows messages', function () {
    $result = (new ScanResult)
        ->record('config.env-example-sync', CheckStatus::Failed, [
            new Finding('config.env-example-sync', Severity::Low, 'Keys missing from example: FOO'),
            new Finding('config.env-example-sync', Severity::Low, 'Keys missing from env: BAR'),
        ]);

    $output = new BufferedOutput;
    (new ConsoleReporter)->render($result, $output);
    $text = $output->fetch();

    // Check ID appears once (as the header)
    expect(substr_count($text, 'config.env-example-sync'))->toBe(1);
    // Both finding messages appear
    expect($text)->toContain('Keys missing from example: FOO')
        ->toContain('Keys missing from env: BAR');
});

it('shows file:line for findings that have it', function () {
    $result = (new ScanResult)
        ->record('sql.raw-user-input', CheckStatus::Failed, [
            new Finding(
                checkId: 'sql.raw-user-input',
                severity: Severity::Critical,
                message: 'Raw SQL with user input',
                file: 'app/Http/UserController.php',
                line: 42,
            ),
        ]);

    $output = new BufferedOutput;
    (new ConsoleReporter)->render($result, $output);
    $text = $output->fetch();

    expect($text)->toContain('app/Http/UserController.php:42');
});

it('groups checks under category headers', function () {
    $result = (new ScanResult)
        ->record('config.app-debug', CheckStatus::Passed, [])
        ->record('cookies.session-secure', CheckStatus::Passed, []);

    $output = new BufferedOutput;
    (new ConsoleReporter)->render($result, $output);
    $text = $output->fetch();

    expect($text)->toContain('Application configuration')
        ->toContain('Cookies & sessions');
});

it('hides passed and skipped rows when onlyFailed is true', function () {
    $result = (new ScanResult)
        ->record('config.app-debug', CheckStatus::Passed, [])
        ->record('config.app-env', CheckStatus::Failed, [
            new Finding('config.app-env', Severity::Info, 'APP_ENV is dev'),
        ])
        ->record('dependencies.npm-audit', CheckStatus::Skipped, [], 'no package.json');

    $output = new BufferedOutput;
    (new ConsoleReporter)->render($result, $output, onlyFailed: true);
    $text = $output->fetch();

    expect($text)->not->toContain('config.app-debug')
        ->and($text)->not->toContain('dependencies.npm-audit')
        ->and($text)->toContain('config.app-env');
});

it('skips the whole category section when all checks pass under onlyFailed', function () {
    $result = (new ScanResult)
        ->record('config.app-debug', CheckStatus::Passed, [])
        ->record('cookies.session-secure', CheckStatus::Failed, [
            new Finding('cookies.session-secure', Severity::Critical, 'bad'),
        ]);

    $output = new BufferedOutput;
    (new ConsoleReporter)->render($result, $output, onlyFailed: true);
    $text = $output->fetch();

    // The per-category section header for "Application configuration" should
    // be skipped, but the Report Card still lists all categories — so we look
    // for a "config.app-debug" row instead which only appears in the per-check
    // section.
    expect($text)->not->toContain('config.app-debug')
        ->and($text)->toContain('Cookies & sessions')
        ->and($text)->toContain('cookies.session-secure');
});

it('renders a report card with category bars', function () {
    $result = (new ScanResult)
        ->record('config.app-debug', CheckStatus::Passed, [])
        ->record('config.app-key', CheckStatus::Passed, [])
        ->record('cookies.session-secure', CheckStatus::Failed, [
            new Finding('cookies.session-secure', Severity::Critical, 'fail'),
        ]);

    $output = new BufferedOutput;
    (new ConsoleReporter)->render($result, $output);
    $text = $output->fetch();

    expect($text)->toContain('Report Card')
        ->toContain('Application configuration')
        ->toContain('Cookies & sessions');
});
