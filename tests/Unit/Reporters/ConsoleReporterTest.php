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
        ->toContain('skipped (no package.json)')
        ->toContain('Passed: 1')
        ->toContain('Failed: 1')
        ->toContain('Skipped: 1');
});
